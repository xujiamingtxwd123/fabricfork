package blkstorage

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/pkg/errors"
)

//根据rootDir目录实际的区块信息，构造元信息
//思路：1）根据文件名获取最后一个block file信息
//     2）每个block file满足 LV结构，根据LV结构解析到最后一个block信息
func constructBlockfilesInfo(rootDir string) (*blockfilesInfo, error) {
	var numBlocksInFile int
	var endOffsetLastBlock int64
	var lastBlockNumber uint64
	var lastBlockBytes []byte
	var lastBlock *common.Block

	//找到最后一个block file
	lastFileNum, err := retrieveLastFileSuffix(rootDir)
	if err != nil {
		return nil, err
	}
	if lastFileNum == -1 {
		blkfilesInfo := &blockfilesInfo{
			latestFileNumber:   0,
			latestFileSize:     0,
			noBlockFiles:       true,
			lastPersistedBlock: 0,
		}
		return blkfilesInfo, nil
	}

	//获取lastFileNum 的 block file 文件中 最后一个block信息
	if lastBlockBytes, endOffsetLastBlock, numBlocksInFile, err = scanForLastCompleteBlock(rootDir, lastFileNum, 0); err != nil {
		return nil, err
	}

	//如果最后一个block file 里面一个块都没有，那么需要寻找上一个block file的最后一个区块
	if numBlocksInFile == 0 && lastFileNum > 0 {
		secondLastFileNum := lastFileNum - 1
		if lastBlockBytes, _, _, err = scanForLastCompleteBlock(rootDir, secondLastFileNum, 0); err != nil {
			return nil, err
		}
	}

	//反序列化 找到区块信息
	if lastBlockBytes != nil {
		if lastBlock, err = deserializeBlock(lastBlockBytes); err != nil {
			return nil, err
		}
		lastBlockNumber = lastBlock.Header.Number
	}

	blkfilesInfo := &blockfilesInfo{
		lastPersistedBlock: lastBlockNumber,
		latestFileSize:     int(endOffsetLastBlock),
		latestFileNumber:   lastFileNum,
		noBlockFiles:       lastFileNum == 0 && numBlocksInFile == 0,
	}
	return blkfilesInfo, nil
}

//根据文件前缀找到最后一个block file
func retrieveLastFileSuffix(rootDir string) (int, error) {
	biggestFileNum := -1
	filesInfo, err := ioutil.ReadDir(rootDir)
	if err != nil {
		return -1, errors.Wrapf(err, "error reading dir %s", rootDir)
	}
	for _, fileInfo := range filesInfo {
		name := fileInfo.Name()
		if fileInfo.IsDir() || !isBlockFileName(name) {
			continue
		}
		fileSuffix := strings.TrimPrefix(name, blockfilePrefix)
		fileNum, err := strconv.Atoi(fileSuffix)
		if err != nil {
			return -1, err
		}
		if fileNum > biggestFileNum {
			biggestFileNum = fileNum
		}
	}
	return biggestFileNum, err
}

func loadBootstrappingSnapshotInfo(rootDir string) (*BootstrappingSnapshotInfo, error) {
	bsiBytes, err := ioutil.ReadFile(filepath.Join(rootDir, bootstrappingSnapshotInfoFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Wrapf(err, "error while reading bootstrappingSnapshotInfo file")
	}
	bsi := &BootstrappingSnapshotInfo{}
	if err := proto.Unmarshal(bsiBytes, bsi); err != nil {
		return nil, errors.Wrapf(err, "error while unmarshalling bootstrappingSnapshotInfo")
	}
	return bsi, nil
}

func retrieveFirstBlockNumFromFile(rootDir string, fileNum int) (uint64, error) {
	s, err := newBlockfileStream(rootDir, fileNum, 0)
	if err != nil {
		return 0, err
	}
	defer s.close()
	bb, err := s.nextBlockBytes()
	if err != nil {
		return 0, err
	}
	blockInfo, err := extractSerializedBlockInfo(bb)
	if err != nil {
		return 0, err
	}
	return blockInfo.blockHeader.Number, nil
}

func isBlockFileName(name string) bool {
	return strings.HasPrefix(name, blockfilePrefix)
}

func deriveBlockfilePath(rootDir string, suffixNum int) string {
	return rootDir + "/" + blockfilePrefix + fmt.Sprintf("%06d", suffixNum)
}
