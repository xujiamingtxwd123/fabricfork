package history

import (
	"fabricfork/common/ledger/dataformat"
	"fabricfork/common/ledger/util/leveldbhelper"
)

type DBProvider struct {
	leveldbProvider *leveldbhelper.Provider
}

func NewDBProvider(path string) (*DBProvider, error) {
	levelDBProvider, err := leveldbhelper.NewProvider(
		&leveldbhelper.Conf{
			DBPath:         path,
			ExpectedFormat: dataformat.CurrentFormat,
		},
	)
	if err != nil {
		return nil, err
	}
	return &DBProvider{
		leveldbProvider: levelDBProvider,
	}, nil
}
