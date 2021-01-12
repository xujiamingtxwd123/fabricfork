package blkstorage

import (
	"os"

	"github.com/hyperledger/fabric/common/flogging"
	"github.com/pkg/errors"

	"fabricfork/common/ledger/dataformat"
	"fabricfork/common/ledger/util/leveldbhelper"
)

var logger = flogging.MustGetLogger("blkstorage")

type BlockStoreProvider struct {
	conf            *Conf
	indexConfig     *IndexConfig
	leveldbProvider *leveldbhelper.Provider
}

// block storage提供的服务入口，由kvledger_provider调用获取block store provider
func NewProvider(conf *Conf, indexConfig *IndexConfig) (*BlockStoreProvider, error) {
	dbConf := &leveldbhelper.Conf{
		DBPath:         conf.getIndexDir(),
		ExpectedFormat: dataFormatVersion(indexConfig),
	}

	p, err := leveldbhelper.NewProvider(dbConf)
	if err != nil {
		return nil, err
	}

	dirPath := conf.getChainsDir()
	if _, err := os.Stat(dirPath); err != nil {
		if !os.IsNotExist(err) { // NotExist is the only permitted error type
			return nil, errors.Wrapf(err, "failed to read ledger directory %s", dirPath)
		}

		if err = os.MkdirAll(dirPath, 0755); err != nil {
			return nil, errors.Wrapf(err, "failed to create ledger directory: %s", dirPath)
		}
	}
	return &BlockStoreProvider{conf, indexConfig, p}, nil
}

// 获取某个ledgerid的block store句柄，这里是否考虑缓存该句柄
func (p *BlockStoreProvider) Open(ledgerid string) (*BlockStore, error) {
	indexStoreHandle := p.leveldbProvider.GetDBHandle(ledgerid)
	return newBlockStore(ledgerid, p.conf, p.indexConfig, indexStoreHandle)
}

func dataFormatVersion(indexConfig *IndexConfig) string {
	// in version 2.0 we merged three indexable into one `IndexableAttrTxID`
	if indexConfig.Contains(IndexableAttrTxID) {
		return dataformat.CurrentFormat
	}
	return dataformat.PreviousFormat
}
