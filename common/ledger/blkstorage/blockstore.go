package blkstorage

import (
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/peer"

	"fabricfork/common/ledger"
	"fabricfork/common/ledger/util/leveldbhelper"
)

type BlockStore struct {
	id      string
	conf    *Conf
	fileMgr *blockfileMgr
}

//获取block store句柄，重点是成员变量fileMgr
func newBlockStore(id string, conf *Conf, indexConfig *IndexConfig,
	dbHandle *leveldbhelper.DBHandle) (*BlockStore, error) {
	fileMgr, err := newBlockfileMgr(id, conf, indexConfig, dbHandle)
	if err != nil {
		return nil, err
	}
	return &BlockStore{id, conf, fileMgr}, nil
}

//添加区块
func (store *BlockStore) AddBlock(block *common.Block) error {
	result := store.fileMgr.addBlock(block)
	return result
}

func (store *BlockStore) GetBlockchainInfo() (*common.BlockchainInfo, error) {
	return store.fileMgr.getBlockchainInfo(), nil
}

func (store *BlockStore) RetrieveBlocks(startNum uint64) (ledger.ResultsIterator, error) {
	return store.fileMgr.retrieveBlocks(startNum)
}

func (store *BlockStore) RetrieveBlockByHash(blockHash []byte) (*common.Block, error) {
	return store.fileMgr.retrieveBlockByHash(blockHash)
}

func (store *BlockStore) RetrieveBlockByNumber(blockNum uint64) (*common.Block, error) {
	return store.fileMgr.retrieveBlockByNumber(blockNum)
}

func (store *BlockStore) RetrieveTxByID(txID string) (*common.Envelope, error) {
	return store.fileMgr.retrieveTransactionByID(txID)
}

func (store *BlockStore) RetrieveTxByBlockNumTranNum(blockNum uint64, tranNum uint64) (*common.Envelope, error) {
	return store.fileMgr.retrieveTransactionByBlockNumTranNum(blockNum, tranNum)
}

func (store *BlockStore) RetrieveBlockByTxID(txID string) (*common.Block, error) {
	return store.fileMgr.retrieveBlockByTxID(txID)
}

// RetrieveTxValidationCodeByTxID returns the validation code for the specified txID
func (store *BlockStore) RetrieveTxValidationCodeByTxID(txID string) (peer.TxValidationCode, error) {
	return store.fileMgr.retrieveTxValidationCodeByTxID(txID)
}

// Shutdown shuts down the block store
func (store *BlockStore) Shutdown() {
	store.fileMgr.close()
}
