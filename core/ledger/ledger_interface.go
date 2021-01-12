package ledger

import (
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/peer"
	"time"
)

type Config struct {
	// RootFSPath is the top-level directory where ledger files are stored.
	RootFSPath        string
	PrivateDataConfig *PrivateDataConfig
	HistoryDBConfig   *HistoryDBConfig
	StateDBConfig     *StateDBConfig
}

type HistoryDBConfig struct {
	Enabled bool
}

type Initializer struct {
	Config *Config
}
type PrivateDataConfig struct {
	// BatchesInterval is the minimum duration (milliseconds) between batches
	// for converting ineligible missing data entries into eligible entries.
	BatchesInterval int
	// MatchBatchSize is the maximum size of batches when converting ineligible
	// missing data entries into eligible entries.
	MaxBatchSize int
	// PurgeInterval is the number of blocks to wait until purging expired
	// private data entries.
	PurgeInterval int
	// The missing data entries are classified into three categories:
	// (1) eligible prioritized
	// (2) eligible deprioritized
	// (3) ineligible
	// The reconciler would fetch the eligible prioritized missing data
	// from other peers. A chance for eligible deprioritized missing data
	// would be given after every DeprioritizedDataReconcilerInterval
	DeprioritizedDataReconcilerInterval time.Duration
}

type StateDBConfig struct {
	// StateDatabase is the database to use for storing last known state.  The
	// two supported options are "goleveldb" and "CouchDB".
	StateDatabase string
	// CouchDB is the configuration for CouchDB.  It is used when StateDatabase
	// is set to "CouchDB".
	CouchDB *CouchDBConfig
}

type CouchDBConfig struct {
	// Address is the hostname:port of the CouchDB database instance.
	Address string
	// Username is the username used to authenticate with CouchDB.  This username
	// must have read and write access permissions.
	Username string
	// Password is the password for Username.
	Password string
	// MaxRetries is the maximum number of times to retry CouchDB operations on
	// failure.
	MaxRetries int
	// MaxRetriesOnStartup is the maximum number of times to retry CouchDB operations on
	// failure when initializing the ledger.
	MaxRetriesOnStartup int
	// RequestTimeout is the timeout used for CouchDB operations.
	RequestTimeout time.Duration
	// InternalQueryLimit is the maximum number of records to return internally
	// when querying CouchDB.
	InternalQueryLimit int
	// MaxBatchUpdateSize is the maximum number of records to included in CouchDB
	// bulk update operations.
	MaxBatchUpdateSize int
	// WarmIndexesAfterNBlocks is the number of blocks after which to warm any
	// CouchDB indexes.
	WarmIndexesAfterNBlocks int
	// CreateGlobalChangesDB determines whether or not to create the "_global_changes"
	// system database.
	CreateGlobalChangesDB bool
	// RedoLogPath is the directory where the CouchDB redo log files are stored.
	RedoLogPath string
	// UserCacheSizeMBs denotes the user specified maximum mega bytes (MB) to be allocated
	// for the user state cache (i.e., all chaincodes deployed by the user). Note that
	// UserCacheSizeMBs needs to be a multiple of 32 MB. If it is not a multiple of 32 MB,
	// the peer would round the size to the next multiple of 32 MB.
	UserCacheSizeMBs int
}

type PeerLedger interface {
	commonledger.Ledger
	// GetTransactionByID retrieves a transaction by id
	GetTransactionByID(txID string) (*peer.ProcessedTransaction, error)
	// GetBlockByHash returns a block given it's hash
	GetBlockByHash(blockHash []byte) (*common.Block, error)
	// GetBlockByTxID returns a block which contains a transaction
	GetBlockByTxID(txID string) (*common.Block, error)
	// GetTxValidationCodeByTxID returns reason code of transaction validation
	GetTxValidationCodeByTxID(txID string) (peer.TxValidationCode, error)
	// NewTxSimulator gives handle to a transaction simulator.
	// A client can obtain more than one 'TxSimulator's for parallel execution.
	// Any snapshoting/synchronization should be performed at the implementation level if required
	NewTxSimulator(txid string) (TxSimulator, error)
	// NewQueryExecutor gives handle to a query executor.
	// A client can obtain more than one 'QueryExecutor's for parallel execution.
	// Any synchronization should be performed at the implementation level if required
	NewQueryExecutor() (QueryExecutor, error)
	// NewHistoryQueryExecutor gives handle to a history query executor.
	// A client can obtain more than one 'HistoryQueryExecutor's for parallel execution.
	// Any synchronization should be performed at the implementation level if required
	NewHistoryQueryExecutor() (HistoryQueryExecutor, error)
	// GetPvtDataAndBlockByNum returns the block and the corresponding pvt data.
	// The pvt data is filtered by the list of 'ns/collections' supplied
	// A nil filter does not filter any results and causes retrieving all the pvt data for the given blockNum
	GetPvtDataAndBlockByNum(blockNum uint64, filter PvtNsCollFilter) (*BlockAndPvtData, error)
	// GetPvtDataByNum returns only the pvt data  corresponding to the given block number
	// The pvt data is filtered by the list of 'ns/collections' supplied in the filter
	// A nil filter does not filter any results and causes retrieving all the pvt data for the given blockNum
	GetPvtDataByNum(blockNum uint64, filter PvtNsCollFilter) ([]*TxPvtData, error)
	// CommitLegacy commits the block and the corresponding pvt data in an atomic operation following the v14 validation/commit path
	// TODO: add a new Commit() path that replaces CommitLegacy() for the validation refactor described in FAB-12221
	CommitLegacy(blockAndPvtdata *BlockAndPvtData, commitOpts *CommitOptions) error
	// GetConfigHistoryRetriever returns the ConfigHistoryRetriever
	GetConfigHistoryRetriever() (ConfigHistoryRetriever, error)
	// CommitPvtDataOfOldBlocks commits the private data corresponding to already committed block
	// If hashes for some of the private data supplied in this function does not match
	// the corresponding hash present in the block, the unmatched private data is not
	// committed and instead the mismatch inforation is returned back
	CommitPvtDataOfOldBlocks(reconciledPvtdata []*ReconciledPvtdata, unreconciled MissingPvtDataInfo) ([]*PvtdataHashMismatch, error)
	// GetMissingPvtDataTracker return the MissingPvtDataTracker
	GetMissingPvtDataTracker() (MissingPvtDataTracker, error)
	// DoesPvtDataInfoExist returns true when
	// (1) the ledger has pvtdata associated with the given block number (or)
	// (2) a few or all pvtdata associated with the given block number is missing but the
	//     missing info is recorded in the ledger (or)
	// (3) the block is committed and does not contain any pvtData.
	DoesPvtDataInfoExist(blockNum uint64) (bool, error)
}

type PeerLedgerProvider interface {
	// Create creates a new ledger with the given genesis block.
	// This function guarantees that the creation of ledger and committing the genesis block would an atomic action
	// The chain id retrieved from the genesis block is treated as a ledger id
	Create(genesisBlock *common.Block) (PeerLedger, error)
	// Open opens an already created ledger
	Open(ledgerID string) (PeerLedger, error)
	// Exists tells whether the ledger with given id exists
	Exists(ledgerID string) (bool, error)
	// List lists the ids of the existing ledgers
	List() ([]string, error)
	// Close closes the PeerLedgerProvider
	Close()
}

type NotFoundInIndexErr string

func (NotFoundInIndexErr) Error() string {
	return "Entry not found in index"
}
