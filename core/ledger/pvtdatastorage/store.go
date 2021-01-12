package pvtdatastorage

import "fabricfork/common/ledger/util/leveldbhelper"

type Provider struct {
	dbProvider    *leveldbhelper.Provider
	pvtDataConfig *PrivateDataConfig
}

func NewProvider(conf *PrivateDataConfig) (*Provider, error) {
	dbProvider, err := leveldbhelper.NewProvider(&leveldbhelper.Conf{DBPath: conf.StorePath})
	if err != nil {
		return nil, err
	}
	return &Provider{
		dbProvider:    dbProvider,
		pvtDataConfig: conf,
	}, nil
}
