package stateleveldb

import (
	"fabricfork/common/ledger/dataformat"
	"fabricfork/common/ledger/util/leveldbhelper"
	"fabricfork/core/ledger/kvledger/txmgmt/statedb"
)

type VersionedDBProvider struct {
	dbProvider *leveldbhelper.Provider
}

func NewVersionedDBProvider(dbPath string) (*VersionedDBProvider, error) {
	dbProvider, err := leveldbhelper.NewProvider(
		&leveldbhelper.Conf{
			DBPath:         dbPath,
			ExpectedFormat: dataformat.CurrentFormat,
		})
	if err != nil {
		return nil, err
	}
	return &VersionedDBProvider{dbProvider}, nil
}

func (provider *VersionedDBProvider) GetDBHandle(dbName string, namespaceProvider statedb.NamespaceProvider) (statedb.VersionedDB, error) {
	return newVersionedDB(provider.dbProvider.GetDBHandle(dbName), dbName), nil
}

// Close closes the underlying db
func (provider *VersionedDBProvider) Close() {
	provider.dbProvider.Close()
}

type versionedDB struct {
	db     *leveldbhelper.DBHandle
	dbName string
}

// newVersionedDB constructs an instance of VersionedDB
func newVersionedDB(db *leveldbhelper.DBHandle, dbName string) *versionedDB {
	return &versionedDB{db, dbName}
}
