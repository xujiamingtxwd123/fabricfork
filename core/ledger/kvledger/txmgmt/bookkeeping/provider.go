package bookkeeping

import (
	"fabricfork/common/ledger/util/leveldbhelper"
	"fmt"
)

type Category int

// Provider provides handle to different bookkeepers for the given ledger
type Provider interface {
	// GetDBHandle returns a db handle that can be used for maintaining the bookkeeping of a given category
	GetDBHandle(ledgerID string, cat Category) *leveldbhelper.DBHandle
	// Close closes the BookkeeperProvider
	Close()
}

type provider struct {
	dbProvider *leveldbhelper.Provider
}

// NewProvider instantiates a new provider
func NewProvider(dbPath string) (Provider, error) {
	dbProvider, err := leveldbhelper.NewProvider(&leveldbhelper.Conf{DBPath: dbPath})
	if err != nil {
		return nil, err
	}
	return &provider{dbProvider: dbProvider}, nil
}

// GetDBHandle implements the function in the interface 'BookkeeperProvider'
func (provider *provider) GetDBHandle(ledgerID string, cat Category) *leveldbhelper.DBHandle {
	return provider.dbProvider.GetDBHandle(fmt.Sprintf(ledgerID+"/%d", cat))
}

// Close implements the function in the interface 'BookKeeperProvider'
func (provider *provider) Close() {
	provider.dbProvider.Close()
}
