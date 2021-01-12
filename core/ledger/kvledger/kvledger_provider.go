package kvledger

import (
	"fabricfork/core/ledger/history"
	"fabricfork/core/ledger/kvledger/txmgmt/bookkeeping"
	"fabricfork/core/ledger/kvledger/txmgmt/privacyenabledstate"
	"fabricfork/core/ledger/pvtdatastorage"

	"github.com/hyperledger/fabric/common/flogging"
	"github.com/pkg/errors"

	"fabricfork/common/ledger/blkstorage"
	"fabricfork/common/ledger/util/leveldbhelper"
	"fabricfork/core/ledger"
)

var ErrNonExistingLedgerID = errors.New("LedgerID does not exist")
var ErrLedgerIDExists = errors.New("LedgerID already exists")
var logger = flogging.MustGetLogger("kvledger")
var formatKey = []byte("f")
var ledgerKeyPrefix = []byte{'l'}
var metadataKeyPrefix = []byte{'s'}
var metadataKeyStop = []byte{'s' + 1}
var underConstructionLedgerKey = []byte("underConstructionLedgerKey")
var attrsToIndex = []blkstorage.IndexableAttr{
	blkstorage.IndexableAttrBlockHash,
	blkstorage.IndexableAttrBlockNum,
	blkstorage.IndexableAttrTxID,
	blkstorage.IndexableAttrBlockNumTranNum,
}

const maxBlockFileSize = 64 * 1024 * 1024

type Provider struct {
	idStore              *idStore
	blkStoreProvider     *blkstorage.BlockStoreProvider
	pvtdataStoreProvider *pvtdatastorage.Provider
	dbProvider           *privacyenabledstate.DBProvider
	historydbProvider    *history.DBProvider
	//configHistoryMgr     *confighistory.Mgr TODO xjm
	stateListeners      []ledger.StateListener
	bookkeepingProvider bookkeeping.Provider
	initializer         *ledger.Initializer
	collElgNotifier     *collElgNotifier
	//stats                *stats TODO xjm
	fileLock *leveldbhelper.FileLock
}

func NewProvider() (*Provider, error) {
	p := &Provider{}
	if err := p.initLedgerIDInventory(); err != nil {
		return nil, err
	}
	if err := p.initBlockStoreProvider(); err != nil {
		return nil, err
	}
	if err := p.initPvtDataStoreProvider(); err != nil {
		return nil, err
	}
	if err := p.initHistoryDBProvider(); err != nil {
		return nil, err
	}
	if err := p.initStateDBProvider(); err != nil {
		return nil, err
	}

	p.recoverUnderConstructionLedger()
	//	p.initSnapshotDir() TODO xjm

	return p, nil
}

func (p *Provider) initLedgerIDInventory() error {
	idStore, err := openIDStore(LedgerProviderPath(p.initializer.Config.RootFSPath))
	if err != nil {
		return err
	}
	p.idStore = idStore
	return nil
}

func (p *Provider) initBlockStoreProvider() error {
	indexConfig := &blkstorage.IndexConfig{AttrsToIndex: attrsToIndex}
	blkStoreProvider, err := blkstorage.NewProvider(
		blkstorage.NewConf(
			BlockStorePath(p.initializer.Config.RootFSPath),
			maxBlockFileSize,
		),
		indexConfig,
	)
	if err != nil {
		return err
	}
	p.blkStoreProvider = blkStoreProvider
	return nil
}

func (p *Provider) initPvtDataStoreProvider() error {
	privateDataConfig := &pvtdatastorage.PrivateDataConfig{
		PrivateDataConfig: p.initializer.Config.PrivateDataConfig,
		StorePath:         PvtDataStorePath(p.initializer.Config.RootFSPath),
	}
	pvtdataStoreProvider, err := pvtdatastorage.NewProvider(privateDataConfig)
	if err != nil {
		return err
	}
	p.pvtdataStoreProvider = pvtdataStoreProvider
	return nil
}

func (p *Provider) initHistoryDBProvider() error {
	if !p.initializer.Config.HistoryDBConfig.Enabled {
		return nil
	}
	// Initialize the history database (index for history of values by key)
	historydbProvider, err := history.NewDBProvider(
		HistoryDBPath(p.initializer.Config.RootFSPath),
	)
	if err != nil {
		return err
	}
	p.historydbProvider = historydbProvider
	return nil
}

func (p *Provider) recoverUnderConstructionLedger() {
	//TODO xjm
}

func (p *Provider) initStateDBProvider() error {
	var err error
	p.bookkeepingProvider, err = bookkeeping.NewProvider(
		BookkeeperDBPath(p.initializer.Config.RootFSPath),
	)
	if err != nil {
		return err
	}
	stateDB := &privacyenabledstate.StateDBConfig{
		StateDBConfig: p.initializer.Config.StateDBConfig,
		LevelDBPath:   StateDBPath(p.initializer.Config.RootFSPath),
	}
	p.dbProvider, err = privacyenabledstate.NewDBProvider(
		p.bookkeepingProvider,
		stateDB,
	)
	return err
}
