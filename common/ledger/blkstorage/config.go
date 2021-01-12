package blkstorage

import "path/filepath"

type Conf struct {
	blockStorageDir  string
	maxBlockfileSize int
}

const (
	//chains下为存储各ledgerID的区块信息
	ChainsDir = "chains"
	//为这些区块创建的索引信息
	IndexDir                = "index"
	defaultMaxBlockfileSize = 64 * 1024 * 1024
)

/*
	blockStorageDir 为存储目录的chains目录下
*/
func NewConf(blockStorageDir string, maxBlockfileSize int) *Conf {
	if maxBlockfileSize <= 0 {
		maxBlockfileSize = defaultMaxBlockfileSize
	}
	return &Conf{blockStorageDir, maxBlockfileSize}
}

func (conf *Conf) getIndexDir() string {
	return filepath.Join(conf.blockStorageDir, IndexDir)
}

func (conf *Conf) getChainsDir() string {
	return filepath.Join(conf.blockStorageDir, ChainsDir)
}

func (conf *Conf) getLedgerBlockDir(ledgerid string) string {
	return filepath.Join(conf.getChainsDir(), ledgerid)
}
