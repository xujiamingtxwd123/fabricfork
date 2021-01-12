package privacyenabledstate

import (
	"fabricfork/core/ledger/kvledger/txmgmt/bookkeeping"
	"fabricfork/core/ledger/kvledger/txmgmt/statedb"
	stateleveldb "fabricfork/core/ledger/kvledger/txmgmt/statedb/stateleveldb"
)

type DBProvider struct {
	VersionedDBProvider statedb.VersionedDBProvider
	bookkeepingProvider bookkeeping.Provider
}

func NewDBProvider(bookkeeperProvider bookkeeping.Provider, stateDBConf *StateDBConfig) (*DBProvider, error) {
	vdbProvider, err := stateleveldb.NewVersionedDBProvider(stateDBConf.LevelDBPath)
	if err != nil {
		return nil, err
	}
	dbProvider := &DBProvider{vdbProvider, bookkeeperProvider}

	return dbProvider, nil
}
