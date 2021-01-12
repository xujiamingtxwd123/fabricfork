package pvtdatastorage

import (
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric-protos-go/ledger/rwset"
	"github.com/willf/bitset"

	"fabricfork/common/ledger/util/leveldbhelper"
	"fabricfork/core/ledger/pvtdatapolicy"
	"fabricfork/core/ledger"
)

var logger = flogging.MustGetLogger("pvtdatastorage")

type storeEntries struct {
	dataEntries             []*dataEntry
	expiryEntries           []*expiryEntry
	elgMissingDataEntries   map[missingDataKey]*bitset.BitSet
	inelgMissingDataEntries map[missingDataKey]*bitset.BitSet
}

type dataEntry struct {
	key   *dataKey
	value *rwset.CollectionPvtReadWriteSet
}

type expiryEntry struct {
	key   *expiryKey
	value *ExpiryData
}

type expiryKey struct {
	expiringBlk   uint64
	committingBlk uint64
}

type Provider struct {
	dbProvider    *leveldbhelper.Provider
	pvtDataConfig *PrivateDataConfig
}

type blkTranNumKey []byte

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

func (p *Provider) OpenStore(ledgerid string) (*Store, error) {
	dbHandle := p.dbProvider.GetDBHandle(ledgerid)
	s := &Store{
		db:       dbHandle,
		ledgerid: ledgerid,
	}
	if err := s.initState(); err != nil {
		return nil, err
	}
	s.launchCollElgProc()

	return s, nil
}

func (p *Provider) Close() {
	p.dbProvider.Close()
}

type Store struct {
	db                 *leveldbhelper.DBHandle
	ledgerid           string
	isEmpty            bool
	lastCommittedBlock uint64
	purgerLock         sync.Mutex
	batchesInterval    int
	maxBatchSize       int
	collElgProcSync    *collElgProcSync
	btlPolicy       pvtdatapolicy.BTLPolicy
	purgeInterval   uint64
}

func (s *Store) Init(btlPolicy pvtdatapolicy.BTLPolicy) {
	s.btlPolicy = btlPolicy
}

func (s *Store) initState() error {
	var err error
	if s.isEmpty, s.lastCommittedBlock, err = s.getLastCommittedBlockNum(); err != nil {
		return err
	}
	return nil
}

func (s *Store) getLastCommittedBlockNum() (bool, uint64, error) {
	var v []byte
	var err error
	if v, err = s.db.Get(lastCommittedBlkkey); v == nil || err != nil {
		return true, 0, err
	}
	return false, decodeLastCommittedBlockVal(v), nil
}

func (s *Store) launchCollElgProc() {
	go func() {
		if err := s.processCollElgEvents(); err != nil {
			// process collection eligibility events when store is opened -
			// in case there is an unprocessed events from previous run
			logger.Errorw("failed to process collection eligibility events", "err", err)
		}
		//当peer访问权限发生变化的时候 触发这里的调用
		for {
			s.collElgProcSync.waitForNotification()
			if err := s.processCollElgEvents(); err != nil {
				logger.Errorw("failed to process collection eligibility events", "err", err)
			}
			s.collElgProcSync.done()
		}
	}()
}

//当某个节点可以合法访问私有数据后，调用该方法，将原来非法数据删除，添加到合法数据集合
func (s *Store) processCollElgEvents() error {
	s.purgerLock.Lock()
	defer s.purgerLock.Unlock()
	collElgStartKey, collElgEndKey := createRangeScanKeysForCollElg()
	eventItr, err := s.db.GetIterator(collElgStartKey, collElgEndKey)
	if err != nil {
		return err
	}
	defer eventItr.Release()
	batch := s.db.NewUpdateBatch()
	totalEntriesConverted := 0

	for eventItr.Next() {
		collElgKey, collElgVal := eventItr.Key(), eventItr.Value()
		blkNum := decodeCollElgKey(collElgKey)
		CollElgInfo, err := decodeCollElgVal(collElgVal)
		if err != nil {
			logger.Errorf("This error is not expected %s", err)
			continue
		}
		for ns, colls := range CollElgInfo.NsCollMap {
			var coll string
			for _, coll = range colls.Entries {
				startKey, endKey := createRangeScanKeysForInelgMissingData(blkNum, ns, coll)
				collItr, err := s.db.GetIterator(startKey, endKey)
				if err != nil {
					return err
				}
				collEntriesConverted := 0
				for collItr.Next() {
					originalKey, originalVal := collItr.Key(), collItr.Value()
					modifiedKey := decodeInelgMissingDataKey(originalKey)
					batch.Delete(originalKey)
					copyVal := make([]byte, len(originalVal))
					copy(copyVal, originalVal)
					batch.Put(
						encodeElgPrioMissingDataKey(modifiedKey),
						copyVal,
					)
					collEntriesConverted++
					if batch.Len() > s.maxBatchSize {
						s.db.WriteBatch(batch, true)
						batch.Reset()
						sleepTime := time.Duration(s.batchesInterval)
						logger.Infof("Going to sleep for %d milliseconds between batches. Entries for [ns=%s, coll=%s] converted so far = %d",
							sleepTime, ns, coll, collEntriesConverted)
						s.purgerLock.Unlock()
						time.Sleep(sleepTime * time.Millisecond)
						s.purgerLock.Lock()
					}
				}
				collItr.Release()
				totalEntriesConverted += collEntriesConverted
			}
		}
	}
	s.db.WriteBatch(batch, true)
	return nil
}

func (s *Store) nextBlockNum() uint64 {
	if s.isEmpty {
		return 0
	}
	return atomic.LoadUint64(&s.lastCommittedBlock) + 1
}

func (s *Store) Commit(blockNum uint64, pvtData []*ledger.TxPvtData, missingPvtData ledger.TxMissingPvtDataMap) error {
	expectedBlockNum := s.nextBlockNum()
	if expectedBlockNum != blockNum {
		return &ErrIllegalArgs{fmt.Sprintf("Expected block number=%d, received block number=%d", expectedBlockNum, blockNum)}
	}
	batch := s.db.NewUpdateBatch()
	var err error
	var key, val []byte

	storeEntries, err := prepareStoreEntries(blockNum, pvtData, s.btlPolicy, missingPvtData)
	if err != nil {
		return err
	}

	//存储隐私数据
	for _, dataEntry := range storeEntries.dataEntries {
		key = encodeDataKey(dataEntry.key)
		if val, err = encodeDataValue(dataEntry.value); err != nil {
			return err
		}
		batch.Put(key, val)
	}

	////存储隐私数据过期设置
	for _, expiryEntry := range storeEntries.expiryEntries {
		key = encodeExpiryKey(expiryEntry.key)
		if val, err = encodeExpiryValue(expiryEntry.value); err != nil {
			return err
		}
		batch.Put(key, val)
	}

	//存储miss 合法访问数据
	for missingDataKey, missingDataValue := range storeEntries.elgMissingDataEntries {
		key = encodeElgPrioMissingDataKey(&missingDataKey)

		if val, err = encodeMissingDataValue(missingDataValue); err != nil {
			return err
		}
		batch.Put(key, val)
	}

	//存储miss 无法访问数据
	for missingDataKey, missingDataValue := range storeEntries.inelgMissingDataEntries {
		key = encodeInelgMissingDataKey(&missingDataKey)

		if val, err = encodeMissingDataValue(missingDataValue); err != nil {
			return err
		}
		batch.Put(key, val)
	}

	committingBlockNum := s.nextBlockNum()
	batch.Put(lastCommittedBlkkey, encodeLastCommittedBlockVal(committingBlockNum))
	if err := s.db.WriteBatch(batch, true); err != nil {
		return err
	}
	s.isEmpty = false
	atomic.StoreUint64(&s.lastCommittedBlock, committingBlockNum)
	s.performPurgeIfScheduled(committingBlockNum)
	return nil
}

func (s *Store) performPurgeIfScheduled(latestCommittedBlk uint64) {
	if latestCommittedBlk%s.purgeInterval != 0 {
		return
	}
	go func() {
		s.purgerLock.Lock()
		defer s.purgerLock.Unlock()
		err := s.purgeExpiredData(0, latestCommittedBlk)
		if err != nil {
			logger.Warningf("Could not purge data from pvtdata store:%s", err)
		}
	}()
}

func (s *Store) purgeExpiredData(minBlkNum, maxBlkNum uint64) error {
	expiryEntries, err := s.retrieveExpiryEntries(minBlkNum, maxBlkNum)
	if err != nil || len(expiryEntries) == 0 {
		return err
	}
	batch := s.db.NewUpdateBatch()
	for _, expiryEntry := range expiryEntries {
		batch.Delete(encodeExpiryKey(expiryEntry.key))
		dataKeys, missingDataKeys := deriveKeys(expiryEntry)

		for _, dataKey := range dataKeys {
			batch.Delete(encodeDataKey(dataKey))
		}
		for _, missingDataKey := range missingDataKeys {
			batch.Delete(
				encodeElgPrioMissingDataKey(missingDataKey),
			)
			batch.Delete(
				encodeElgDeprioMissingDataKey(missingDataKey),
			)
			batch.Delete(
				encodeInelgMissingDataKey(missingDataKey),
			)
		}
		if err := s.db.WriteBatch(batch, false); err != nil {
			return err
		}
		batch.Reset()
	}
	return nil
}

func (s *Store) retrieveExpiryEntries(minBlkNum, maxBlkNum uint64) ([]*expiryEntry, error) {
	startKey, endKey := getExpiryKeysForRangeScan(minBlkNum, maxBlkNum)
	logger.Debugf("retrieveExpiryEntries(): startKey=%#v, endKey=%#v", startKey, endKey)
	itr, err := s.db.GetIterator(startKey, endKey)
	if err != nil {
		return nil, err
	}
	defer itr.Release()

	var expiryEntries []*expiryEntry
	for itr.Next() {
		expiryKeyBytes := itr.Key()
		expiryValueBytes := itr.Value()
		expiryKey, err := decodeExpiryKey(expiryKeyBytes)
		if err != nil {
			return nil, err
		}
		expiryValue, err := decodeExpiryValue(expiryValueBytes)
		if err != nil {
			return nil, err
		}
		expiryEntries = append(expiryEntries, &expiryEntry{key: expiryKey, value: expiryValue})
	}
	return expiryEntries, nil
}

func (s *Store) GetPvtDataByBlockNum(blockNum uint64, filter ledger.PvtNsCollFilter) ([]*ledger.TxPvtData, error) {
	if s.isEmpty {
		return nil, &ErrOutOfRange{"The store is empty"}
	}
	lastCommittedBlock := atomic.LoadUint64(&s.lastCommittedBlock)
	if blockNum > lastCommittedBlock {
		return nil, &ErrOutOfRange{fmt.Sprintf("Last committed block=%d, block requested=%d", lastCommittedBlock, blockNum)}
	}
	startKey, endKey := getDataKeysForRangeScanByBlockNum(blockNum)
	itr, err := s.db.GetIterator(startKey, endKey)
	if err != nil {
		return nil, err
	}
	defer itr.Release()
	var blockPvtdata []*ledger.TxPvtData
	var currentTxNum uint64
	var currentTxWsetAssember *txPvtdataAssembler
	firstItr := true
	for itr.Next() {
		dataKeyBytes := itr.Key()
		v11Fmt, err := v11Format(dataKeyBytes)
		if err != nil {
			return nil, err
		}
		if v11Fmt {
			return v11RetrievePvtdata(itr, filter)
		}
	}
}

func createRangeScanKeysForCollElg() (startKey, endKey []byte) {
	return encodeCollElgKey(math.MaxUint64),
		encodeCollElgKey(0)
}

type collElgProcSync struct {
	notification, procComplete chan bool
}

func (c *collElgProcSync) notify() {
	select {
	case c.notification <- true:
		logger.Debugf("Signaled to collection eligibility processing routine")
	default: //noop
		logger.Debugf("Previous signal still pending. Skipping new signal")
	}
}

func (c *collElgProcSync) waitForNotification() {
	<-c.notification
}

func (c *collElgProcSync) done() {
	select {
	case c.procComplete <- true:
	default:
	}
}

func (c *collElgProcSync) waitForDone() {
	<-c.procComplete
}

type ErrIllegalArgs struct {
	msg string
}

func (err *ErrIllegalArgs) Error() string {
	return err.msg
}

type ErrOutOfRange struct {
	msg string
}

func (err *ErrOutOfRange) Error() string {
	return err.msg
}