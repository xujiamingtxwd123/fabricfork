package blkstorage

import (
	"bytes"
	"fmt"
	"math"
	"sync"
	"sync/atomic"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/pkg/errors"

	"fabricfork/common/ledger/util"
	"fabricfork/common/ledger/util/leveldbhelper"
	"fabricfork/protoutil"
)

//数据库Key值，负责存储当前处理到的块文件元信息
var blkMgrInfoKey = []byte("blkMgrInfo")

const (
	//每个区块文件命名前缀
	blockfilePrefix = "blockfile_"
	//快照记录的元信息
	bootstrappingSnapshotInfoFile = "bootstrappingSnapshot.info"
)

type blockfileMgr struct {
	//块文件存储目录，为chains/chains/{ledgerid}/
	rootDir                   string
	conf                      *Conf
	db                        *leveldbhelper.DBHandle
	index                     *blockIndex
	blockfilesInfo            *blockfilesInfo
	bootstrappingSnapshotInfo *BootstrappingSnapshotInfo
	blkfilesInfoCond          *sync.Cond
	currentFileWriter         *blockfileWriter
	bcInfo                    atomic.Value
}

//为某个ledgerid创建block file 的 manager 句柄，以及执行初始化操作
func newBlockfileMgr(id string, conf *Conf, indexConfig *IndexConfig, indexStore *leveldbhelper.DBHandle) (*blockfileMgr, error) {
	channelIDDir := conf.getLedgerBlockDir(id)
	_, err := util.CreateDirIfMissing(channelIDDir)
	if err != nil {
		panic(fmt.Sprintf("Error creating block storage root dir [%s]: %s", channelIDDir, err))
	}
	mgr := &blockfileMgr{rootDir: channelIDDir, conf: conf, db: indexStore}
	//获取上次处理到的块文件信息
	blockfilesInfo, err := mgr.loadBlkfilesInfo()
	if err != nil {
		panic(fmt.Sprintf("Could not get block file info for current block file from db: %s", err))
	}
	if blockfilesInfo == nil {
		//如果数据库值丢失或不存在，根据实际的区块文件 构造blockfilesinfo
		if blockfilesInfo, err = constructBlockfilesInfo(channelIDDir); err != nil {
			panic(fmt.Sprintf("Could not build blockfilesInfo info from block files: %s", err))
		}
	} else {
		syncBlockfilesInfoFromFS(channelIDDir, blockfilesInfo)
	}

	//创建last block file的操作句柄
	currentFileWriter, err := newBlockfileWriter(deriveBlockfilePath(channelIDDir, blockfilesInfo.latestFileNumber))
	if err != nil {
		panic(fmt.Sprintf("Could not open writer to current file: %s", err))
	}
	//跳过指定offset
	err = currentFileWriter.truncateFile(blockfilesInfo.latestFileSize)
	if err != nil {
		panic(fmt.Sprintf("Could not truncate current file to known size in db: %s", err))
	}

	if mgr.index, err = newBlockIndex(indexConfig, indexStore); err != nil {
		panic(fmt.Sprintf("error in block index: %s", err))
	}
	mgr.blockfilesInfo = blockfilesInfo
	// 从数据库中读取最新的快照信息
	bsi, err := loadBootstrappingSnapshotInfo(channelIDDir)
	if err != nil {
		return nil, err
	}
	mgr.bootstrappingSnapshotInfo = bsi
	mgr.currentFileWriter = currentFileWriter
	mgr.blkfilesInfoCond = sync.NewCond(&sync.Mutex{})

	//数据库中记录最新的index是哪个block num，补齐中间的区块索引差
	if err := mgr.syncIndex(); err != nil {
		return nil, err
	}
	bcInfo := &common.BlockchainInfo{}

	if mgr.bootstrappingSnapshotInfo != nil {
		bcInfo.Height = mgr.bootstrappingSnapshotInfo.LastBlockNum + 1
		bcInfo.CurrentBlockHash = mgr.bootstrappingSnapshotInfo.LastBlockHash
		bcInfo.PreviousBlockHash = mgr.bootstrappingSnapshotInfo.PreviousBlockHash
	}

	if !blockfilesInfo.noBlockFiles {
		lastBlockHeader, err := mgr.retrieveBlockHeaderByNumber(blockfilesInfo.lastPersistedBlock)
		if err != nil {
			panic(fmt.Sprintf("Could not retrieve header of the last block form file: %s", err))
		}
		lastBlockHash := protoutil.BlockHeaderHash(lastBlockHeader)
		previousBlockHash := lastBlockHeader.PreviousHash
		bcInfo = &common.BlockchainInfo{
			Height:            blockfilesInfo.lastPersistedBlock + 1,
			CurrentBlockHash:  lastBlockHash,
			PreviousBlockHash: previousBlockHash}
	}
	mgr.bcInfo.Store(bcInfo)
	return mgr, nil
}

func (mgr *blockfileMgr) retrieveBlockHeaderByNumber(blockNum uint64) (*common.BlockHeader, error) {
	if blockNum < mgr.firstPossibleBlockNumberInBlockFiles() {
		return nil, errors.Errorf(
			"cannot serve block [%d]. The ledger is bootstrapped from a snapshot. First available block = [%d]",
			blockNum, mgr.firstPossibleBlockNumberInBlockFiles(),
		)
	}
	loc, err := mgr.index.getBlockLocByBlockNum(blockNum)
	if err != nil {
		return nil, err
	}
	blockBytes, err := mgr.fetchBlockBytes(loc)
	if err != nil {
		return nil, err
	}
	info, err := extractSerializedBlockInfo(blockBytes)
	if err != nil {
		return nil, err
	}
	return info.blockHeader, nil
}

func (mgr *blockfileMgr) fetchBlockBytes(lp *fileLocPointer) ([]byte, error) {
	stream, err := newBlockfileStream(mgr.rootDir, lp.fileSuffixNum, int64(lp.offset))
	if err != nil {
		return nil, err
	}
	defer stream.close()
	b, err := stream.nextBlockBytes()
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (mgr *blockfileMgr) firstPossibleBlockNumberInBlockFiles() uint64 {
	if mgr.bootstrappingSnapshotInfo == nil {
		return 0
	}
	return mgr.bootstrappingSnapshotInfo.LastBlockNum + 1
}

func (mgr *blockfileMgr) bootstrappedFromSnapshot() bool {
	return mgr.firstPossibleBlockNumberInBlockFiles() > 0
}

func (mgr *blockfileMgr) syncIndex() error {
	nextIndexableBlock := uint64(0)
	//从数据库中读取区块索引对应的块号
	lastBlockIndexed, err := mgr.index.getLastBlockIndexed()
	if err != nil {
		if err != ErrIndexSavePointKeyNotPresent {
			return err
		}
	} else {
		nextIndexableBlock = lastBlockIndexed + 1
	}

	if nextIndexableBlock == 0 && mgr.bootstrappedFromSnapshot() {
		return errors.Errorf(
			"cannot sync index with block files. blockstore is bootstrapped from a snapshot and first available block=[%d]",
			mgr.firstPossibleBlockNumberInBlockFiles(),
		)
	}
	if mgr.blockfilesInfo.noBlockFiles {
		return nil
	}

	startFileNum := 0
	startOffset := 0
	skipFirstBlock := false
	endFileNum := mgr.blockfilesInfo.latestFileNumber

	firstAvailableBlkNum, err := retrieveFirstBlockNumFromFile(mgr.rootDir, 0)
	if err != nil {
		return err
	}

	//获取这个块号 所在的 block_file  offset
	if nextIndexableBlock > firstAvailableBlkNum {
		logger.Debugf("Last block indexed [%d], Last block present in block files [%d]", lastBlockIndexed, mgr.blockfilesInfo.lastPersistedBlock)
		var flp *fileLocPointer
		if flp, err = mgr.index.getBlockLocByBlockNum(lastBlockIndexed); err != nil {
			return err
		}
		startFileNum = flp.fileSuffixNum
		startOffset = flp.locPointer.offset
		skipFirstBlock = true
	}

	//找到index 没有的file num 范围
	var stream *blockStream
	if stream, err = newBlockStream(mgr.rootDir, startFileNum, int64(startOffset), endFileNum); err != nil {
		return err
	}
	var blockBytes []byte
	var blockPlacementInfo *blockPlacementInfo

	if skipFirstBlock {
		if blockBytes, _, err = stream.nextBlockBytesAndPlacementInfo(); err != nil {
			return err
		}
		if blockBytes == nil {
			return errors.Errorf("block bytes for block num = [%d] should not be nil here. The indexes for the block are already present",
				lastBlockIndexed)
		}
	}

	blockIdxInfo := &blockIdxInfo{}
	for {
		//读取每一个block信息
		if blockBytes, blockPlacementInfo, err = stream.nextBlockBytesAndPlacementInfo(); err != nil {
			return err
		}
		if blockBytes == nil {
			break
		}
		//获取区块的header data metadata数据
		info, err := extractSerializedBlockInfo(blockBytes)
		if err != nil {
			return err
		}
		//跳过存储头 重新计算相对偏移（相对于block 数据）
		numBytesToShift := int(blockPlacementInfo.blockBytesOffset - blockPlacementInfo.blockStartOffset)
		for _, offset := range info.txOffsets {
			offset.loc.offset += numBytesToShift
		}

		//Update the blockIndexInfo with what was actually stored in file system
		blockIdxInfo.blockHash = protoutil.BlockHeaderHash(info.blockHeader)
		blockIdxInfo.blockNum = info.blockHeader.Number
		blockIdxInfo.flp = &fileLocPointer{fileSuffixNum: blockPlacementInfo.fileNum,
			locPointer: locPointer{offset: int(blockPlacementInfo.blockStartOffset)}}
		blockIdxInfo.txOffsets = info.txOffsets
		blockIdxInfo.metadata = info.metadata
		if err = mgr.index.indexBlock(blockIdxInfo); err != nil {
			return err
		}
	}
	return nil
}

func (mgr *blockfileMgr) addBlock(block *common.Block) error {
	bcInfo := mgr.getBlockchainInfo()
	if block.Header.Number != bcInfo.Height {
		return errors.Errorf(
			"block number should have been %d but was %d",
			mgr.getBlockchainInfo().Height, block.Header.Number,
		)
	}
	if !bytes.Equal(block.Header.PreviousHash, bcInfo.CurrentBlockHash) {
		return errors.Errorf(
			"unexpected Previous block hash. Expected PreviousHash = [%x], PreviousHash referred in the latest block= [%x]",
			bcInfo.CurrentBlockHash, block.Header.PreviousHash,
		)
	}
	blockBytes, info, err := serializeBlock(block)
	if err != nil {
		return errors.WithMessage(err, "error serializing block")
	}
	blockHash := protoutil.BlockHeaderHash(block.Header)
	txOffsets := info.txOffsets
	currentOffset := mgr.blockfilesInfo.latestFileSize
	blockBytesLen := len(blockBytes)
	blockBytesEncodedLen := proto.EncodeVarint(uint64(blockBytesLen))
	totalBytesToAppend := blockBytesLen + len(blockBytesEncodedLen)
	//如果区块大小超过最大值，准备写入到下个区块
	if currentOffset+totalBytesToAppend > mgr.conf.maxBlockfileSize {
		mgr.moveToNextFile()
		currentOffset = 0
	}

	//将LV结构写入区块
	err = mgr.currentFileWriter.append(blockBytesEncodedLen, false)
	if err == nil {
		//append the actual block bytes to the file
		err = mgr.currentFileWriter.append(blockBytes, true)
	}

	if err != nil {
		//如果失败重置offset
		truncateErr := mgr.currentFileWriter.truncateFile(mgr.blockfilesInfo.latestFileSize)
		if truncateErr != nil {
			panic(fmt.Sprintf("Could not truncate current file to known size after an error during block append: %s", err))
		}
		return errors.WithMessage(err, "error appending block to file")
	}

	currentBlkfilesInfo := mgr.blockfilesInfo
	newBlkfilesInfo := &blockfilesInfo{
		latestFileNumber:   currentBlkfilesInfo.latestFileNumber,
		latestFileSize:     currentBlkfilesInfo.latestFileSize + totalBytesToAppend,
		noBlockFiles:       false,
		lastPersistedBlock: block.Header.Number}

	if err = mgr.saveBlkfilesInfo(newBlkfilesInfo, false); err != nil {
		truncateErr := mgr.currentFileWriter.truncateFile(currentBlkfilesInfo.latestFileSize)
		if truncateErr != nil {
			panic(fmt.Sprintf("Error in truncating current file to known size after an error in saving blockfiles info: %s", err))
		}
		return errors.WithMessage(err, "error saving blockfiles file info to db")
	}

	//Index block file location pointer updated with file suffex and offset for the new block
	blockFLP := &fileLocPointer{fileSuffixNum: newBlkfilesInfo.latestFileNumber}
	blockFLP.offset = currentOffset
	// shift the txoffset because we prepend length of bytes before block bytes
	for _, txOffset := range txOffsets {
		txOffset.loc.offset += len(blockBytesEncodedLen)
	}
	//save the index in the database
	if err = mgr.index.indexBlock(&blockIdxInfo{
		blockNum: block.Header.Number, blockHash: blockHash,
		flp: blockFLP, txOffsets: txOffsets, metadata: block.Metadata}); err != nil {
		return err
	}
	mgr.updateBlockfilesInfo(newBlkfilesInfo)
	mgr.updateBlockchainInfo(blockHash, block)
	return nil
}

func (mgr *blockfileMgr) updateBlockchainInfo(latestBlockHash []byte, latestBlock *common.Block) {
	currentBCInfo := mgr.getBlockchainInfo()
	newBCInfo := &common.BlockchainInfo{
		Height:            currentBCInfo.Height + 1,
		CurrentBlockHash:  latestBlockHash,
		PreviousBlockHash: latestBlock.Header.PreviousHash}

	mgr.bcInfo.Store(newBCInfo)
}

func (mgr *blockfileMgr) moveToNextFile() {
	blkfilesInfo := &blockfilesInfo{
		latestFileNumber:   mgr.blockfilesInfo.latestFileNumber + 1,
		latestFileSize:     0,
		lastPersistedBlock: mgr.blockfilesInfo.lastPersistedBlock}
	nextFileWriter, err := newBlockfileWriter(
		deriveBlockfilePath(mgr.rootDir, blkfilesInfo.latestFileNumber))

	if err != nil {
		panic(fmt.Sprintf("Could not open writer to next file: %s", err))
	}
	mgr.currentFileWriter.close()
	err = mgr.saveBlkfilesInfo(blkfilesInfo, true)
	if err != nil {
		panic(fmt.Sprintf("Could not save next block file info to db: %s", err))
	}
	mgr.currentFileWriter = nextFileWriter
	mgr.updateBlockfilesInfo(blkfilesInfo)
}

func (mgr *blockfileMgr) retrieveBlocks(startNum uint64) (*blocksItr, error) {
	if startNum < mgr.firstPossibleBlockNumberInBlockFiles() {
		return nil, errors.Errorf(
			"cannot serve block [%d]. The ledger is bootstrapped from a snapshot. First available block = [%d]",
			startNum, mgr.firstPossibleBlockNumberInBlockFiles(),
		)
	}
	return newBlockItr(mgr, startNum), nil
}

func (mgr *blockfileMgr) retrieveBlockByHash(blockHash []byte) (*common.Block, error) {
	loc, err := mgr.index.getBlockLocByHash(blockHash)
	if err != nil {
		return nil, err
	}
	return mgr.fetchBlock(loc)
}

func (mgr *blockfileMgr) retrieveBlockByNumber(blockNum uint64) (*common.Block, error) {
	logger.Debugf("retrieveBlockByNumber() - blockNum = [%d]", blockNum)

	// interpret math.MaxUint64 as a request for last block
	if blockNum == math.MaxUint64 {
		blockNum = mgr.getBlockchainInfo().Height - 1
	}
	if blockNum < mgr.firstPossibleBlockNumberInBlockFiles() {
		return nil, errors.Errorf(
			"cannot serve block [%d]. The ledger is bootstrapped from a snapshot. First available block = [%d]",
			blockNum, mgr.firstPossibleBlockNumberInBlockFiles(),
		)
	}
	loc, err := mgr.index.getBlockLocByBlockNum(blockNum)
	if err != nil {
		return nil, err
	}
	return mgr.fetchBlock(loc)
}

func (mgr *blockfileMgr) fetchBlock(lp *fileLocPointer) (*common.Block, error) {
	blockBytes, err := mgr.fetchBlockBytes(lp)
	if err != nil {
		return nil, err
	}
	block, err := deserializeBlock(blockBytes)
	if err != nil {
		return nil, err
	}
	return block, nil
}

func (mgr *blockfileMgr) retrieveTransactionByBlockNumTranNum(blockNum uint64, tranNum uint64) (*common.Envelope, error) {
	logger.Debugf("retrieveTransactionByBlockNumTranNum() - blockNum = [%d], tranNum = [%d]", blockNum, tranNum)
	if blockNum < mgr.firstPossibleBlockNumberInBlockFiles() {
		return nil, errors.Errorf(
			"cannot serve block [%d]. The ledger is bootstrapped from a snapshot. First available block = [%d]",
			blockNum, mgr.firstPossibleBlockNumberInBlockFiles(),
		)
	}
	loc, err := mgr.index.getTXLocByBlockNumTranNum(blockNum, tranNum)
	if err != nil {
		return nil, err
	}
	return mgr.fetchTransactionEnvelope(loc)
}

func (mgr *blockfileMgr) retrieveBlockByTxID(txID string) (*common.Block, error) {
	logger.Debugf("retrieveBlockByTxID() - txID = [%s]", txID)
	loc, err := mgr.index.getBlockLocByTxID(txID)
	if err == errNilValue {
		return nil, errors.Errorf(
			"details for the TXID [%s] not available. Ledger bootstrapped from a snapshot. First available block = [%d]",
			txID, mgr.firstPossibleBlockNumberInBlockFiles())
	}
	if err != nil {
		return nil, err
	}
	return mgr.fetchBlock(loc)
}

func (mgr *blockfileMgr) retrieveTxValidationCodeByTxID(txID string) (peer.TxValidationCode, error) {
	logger.Debugf("retrieveTxValidationCodeByTxID() - txID = [%s]", txID)
	validationCode, err := mgr.index.getTxValidationCodeByTxID(txID)
	if err == errNilValue {
		return peer.TxValidationCode(-1), errors.Errorf(
			"details for the TXID [%s] not available. Ledger bootstrapped from a snapshot. First available block = [%d]",
			txID, mgr.firstPossibleBlockNumberInBlockFiles())
	}
	return validationCode, err
}

func (mgr *blockfileMgr) retrieveTransactionByID(txID string) (*common.Envelope, error) {
	logger.Debugf("retrieveTransactionByID() - txId = [%s]", txID)
	loc, err := mgr.index.getTxLoc(txID)
	if err == errNilValue {
		return nil, errors.Errorf(
			"details for the TXID [%s] not available. Ledger bootstrapped from a snapshot. First available block = [%d]",
			txID, mgr.firstPossibleBlockNumberInBlockFiles())
	}
	if err != nil {
		return nil, err
	}
	return mgr.fetchTransactionEnvelope(loc)
}

func (mgr *blockfileMgr) fetchTransactionEnvelope(lp *fileLocPointer) (*common.Envelope, error) {
	logger.Debugf("Entering fetchTransactionEnvelope() %v\n", lp)
	var err error
	var txEnvelopeBytes []byte
	if txEnvelopeBytes, err = mgr.fetchRawBytes(lp); err != nil {
		return nil, err
	}
	_, n := proto.DecodeVarint(txEnvelopeBytes)
	return protoutil.GetEnvelopeFromBlock(txEnvelopeBytes[n:])
}

func (mgr *blockfileMgr) fetchRawBytes(lp *fileLocPointer) ([]byte, error) {
	filePath := deriveBlockfilePath(mgr.rootDir, lp.fileSuffixNum)
	reader, err := newBlockfileReader(filePath)
	if err != nil {
		return nil, err
	}
	defer reader.close()
	b, err := reader.read(lp.offset, lp.bytesLength)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (mgr *blockfileMgr) updateBlockfilesInfo(blkfilesInfo *blockfilesInfo) {
	mgr.blkfilesInfoCond.L.Lock()
	defer mgr.blkfilesInfoCond.L.Unlock()
	mgr.blockfilesInfo = blkfilesInfo
	//有线程等待 block file info 更新
	mgr.blkfilesInfoCond.Broadcast()
}

func (mgr *blockfileMgr) getBlockchainInfo() *common.BlockchainInfo {
	return mgr.bcInfo.Load().(*common.BlockchainInfo)
}

func (mgr *blockfileMgr) saveBlkfilesInfo(i *blockfilesInfo, sync bool) error {
	b, err := i.marshal()
	if err != nil {
		return err
	}
	if err = mgr.db.Put(blkMgrInfoKey, b, sync); err != nil {
		return err
	}
	return nil
}

func (mgr *blockfileMgr) loadBlkfilesInfo() (*blockfilesInfo, error) {
	var b []byte
	var err error
	if b, err = mgr.db.Get(blkMgrInfoKey); b == nil || err != nil {
		return nil, err
	}
	i := &blockfilesInfo{}
	if err = i.unmarshal(b); err != nil {
		return nil, err
	}
	return i, nil
}

func (mgr *blockfileMgr) close() {
	mgr.currentFileWriter.close()
}

// 根据rootDir、fileNum、startingOffset 解析LV 结构到最后一个块
func scanForLastCompleteBlock(rootDir string, fileNum int, startingOffset int64) ([]byte, int64, int, error) {
	numBlocks := 0
	var lastBlockBytes []byte
	//获取 处理block file的句柄
	blockFileStream, errOpen := newBlockfileStream(rootDir, fileNum, startingOffset)
	if errOpen != nil {
		return nil, 0, 0, errOpen
	}
	defer blockFileStream.close()
	var errRead error
	var blockBytes []byte
	for {
		//解析跳过每个区块
		blockBytes, errRead = blockFileStream.nextBlockBytes()
		if blockBytes == nil || errRead != nil {
			break
		}
		//解析的最后一个区块内容
		lastBlockBytes = blockBytes
		//已经跳过的区块数
		numBlocks++
	}
	if errRead == ErrUnexpectedEndOfBlockfile {
		errRead = nil
	}
	return lastBlockBytes, blockFileStream.currentOffset, numBlocks, errRead
}

//根据block file 更新block file info
func syncBlockfilesInfoFromFS(rootDir string, blkfilesInfo *blockfilesInfo) {
	filePath := deriveBlockfilePath(rootDir, blkfilesInfo.latestFileNumber)
	exists, size, err := util.FileExists(filePath)
	if err != nil {
		panic(fmt.Sprintf("Error in checking whether file [%s] exists: %s", filePath, err))
	}
	if !exists || int(size) == blkfilesInfo.latestFileSize {
		return
	}
	_, endOffsetLastBlock, numBlocks, err := scanForLastCompleteBlock(
		rootDir, blkfilesInfo.latestFileNumber, int64(blkfilesInfo.latestFileSize))
	if err != nil {
		panic(fmt.Sprintf("Could not open current file for detecting last block in the file: %s", err))
	}
	blkfilesInfo.latestFileSize = int(endOffsetLastBlock)
	if numBlocks == 0 {
		return
	}
	if blkfilesInfo.noBlockFiles {
		blkfilesInfo.lastPersistedBlock = uint64(numBlocks - 1)
	} else {
		blkfilesInfo.lastPersistedBlock += uint64(numBlocks)
	}
	blkfilesInfo.noBlockFiles = false
}

type blockfilesInfo struct {
	//block file 已经写到的最后 block file 编号
	latestFileNumber int
	//最后一个block file偏移
	latestFileSize int
	//latestFileNumber 里面是否有block
	noBlockFiles bool
	//block file 最后一个块号
	lastPersistedBlock uint64
}

func (i *blockfilesInfo) unmarshal(b []byte) error {
	buffer := proto.NewBuffer(b)
	var val uint64
	var noBlockFilesMarker uint64
	var err error

	if val, err = buffer.DecodeVarint(); err != nil {
		return err
	}
	i.latestFileNumber = int(val)

	if val, err = buffer.DecodeVarint(); err != nil {
		return err
	}
	i.latestFileSize = int(val)

	if val, err = buffer.DecodeVarint(); err != nil {
		return err
	}
	i.lastPersistedBlock = val
	if noBlockFilesMarker, err = buffer.DecodeVarint(); err != nil {
		return err
	}
	i.noBlockFiles = noBlockFilesMarker == 1
	return nil
}

func (i *blockfilesInfo) marshal() ([]byte, error) {
	buffer := proto.NewBuffer([]byte{})
	var err error
	if err = buffer.EncodeVarint(uint64(i.latestFileNumber)); err != nil {
		return nil, errors.Wrapf(err, "error encoding the latestFileNumber [%d]", i.latestFileNumber)
	}
	if err = buffer.EncodeVarint(uint64(i.latestFileSize)); err != nil {
		return nil, errors.Wrapf(err, "error encoding the latestFileSize [%d]", i.latestFileSize)
	}
	if err = buffer.EncodeVarint(i.lastPersistedBlock); err != nil {
		return nil, errors.Wrapf(err, "error encoding the lastPersistedBlock [%d]", i.lastPersistedBlock)
	}
	var noBlockFilesMarker uint64
	if i.noBlockFiles {
		noBlockFilesMarker = 1
	}
	if err = buffer.EncodeVarint(noBlockFilesMarker); err != nil {
		return nil, errors.Wrapf(err, "error encoding noBlockFiles [%d]", noBlockFilesMarker)
	}
	return buffer.Bytes(), nil
}
