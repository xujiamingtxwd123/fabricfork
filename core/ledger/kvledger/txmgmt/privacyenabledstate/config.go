package privacyenabledstate

import "fabricfork/core/ledger"

type StateDBConfig struct {
	// ledger.StateDBConfig is used to configure the stateDB for the ledger.
	*ledger.StateDBConfig
	// LevelDBPath is the filesystem path when statedb type is "goleveldb".
	// It is internally computed by the ledger component,
	// so it is not in ledger.StateDBConfig and not exposed to other components.
	LevelDBPath string
}
