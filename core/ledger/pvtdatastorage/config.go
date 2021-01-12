package pvtdatastorage

import "fabricfork/core/ledger"

type PrivateDataConfig struct {
	// PrivateDataConfig is used to configure a private data storage provider
	*ledger.PrivateDataConfig
	// StorePath is the filesystem path for private data storage.
	// It is internally computed by the ledger component,
	// so it is not in ledger.PrivateDataConfig and not exposed to other components.
	StorePath string
}
