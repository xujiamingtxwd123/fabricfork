package pvtdatastorage

import (
	"fabricfork/core/ledger"
	"fabricfork/core/ledger/pvtdatapolicy"
	"github.com/hyperledger/fabric-protos-go/ledger/rwset"
	"github.com/willf/bitset"
	"math"
)

func prepareStoreEntries(blockNum uint64, pvtData []*ledger.TxPvtData, btlPolicy pvtdatapolicy.BTLPolicy,
	missingPvtData ledger.TxMissingPvtDataMap) (*storeEntries, error) {
	dataEntries := prepareDataEntries(blockNum, pvtData)

	elgMissingDataEntries, inelgMissingDataEntries := prepareMissingDataEntries(blockNum, missingPvtData)

	expiryEntries, err := prepareExpiryEntries(blockNum, dataEntries, elgMissingDataEntries, inelgMissingDataEntries, btlPolicy)
	if err != nil {
		return nil, err
	}
	return &storeEntries{
		dataEntries:             dataEntries,
		expiryEntries:           expiryEntries,
		elgMissingDataEntries:   elgMissingDataEntries,
		inelgMissingDataEntries: inelgMissingDataEntries,
	}, nil
}

func prepareDataEntries(blockNum uint64, pvtData []*ledger.TxPvtData) []*dataEntry {
	var dataEntries []*dataEntry
	for _, txPvtdata := range pvtData {
		for _, nsPvtdata := range txPvtdata.WriteSet.NsPvtRwset {
			for _, collPvtdata := range nsPvtdata.CollectionPvtRwset {
				txnum := txPvtdata.SeqInBlock
				ns := nsPvtdata.Namespace
				coll := collPvtdata.CollectionName
				dataKey := &dataKey{nsCollBlk{ns, coll, blockNum}, txnum}
				dataEntries = append(dataEntries, &dataEntry{key: dataKey, value: collPvtdata})
			}
		}
	}
	return dataEntries
}

func prepareMissingDataEntries(
	committingBlk uint64,
	missingPvtData ledger.TxMissingPvtDataMap,
) (map[missingDataKey]*bitset.BitSet, map[missingDataKey]*bitset.BitSet) {
	elgMissingDataEntries := make(map[missingDataKey]*bitset.BitSet)
	inelgMissingDataEntries := make(map[missingDataKey]*bitset.BitSet)

	for txNum, missingData := range missingPvtData {
		for _, nsColl := range missingData {
			key := missingDataKey{
				nsCollBlk{
					ns:     nsColl.Namespace,
					coll:   nsColl.Collection,
					blkNum: committingBlk,
				},
			}
			switch nsColl.IsEligible {
			case true:
				if _, ok := elgMissingDataEntries[key]; !ok {
					elgMissingDataEntries[key] = &bitset.BitSet{}
				}
				elgMissingDataEntries[key].Set(uint(txNum))
			default:
				if _, ok := inelgMissingDataEntries[key]; !ok {
					inelgMissingDataEntries[key] = &bitset.BitSet{}
				}
				inelgMissingDataEntries[key].Set(uint(txNum))
			}
		}
	}
	return elgMissingDataEntries, inelgMissingDataEntries
}

func prepareExpiryEntries(committingBlk uint64, dataEntries []*dataEntry, elgMissingDataEntries, inelgMissingDataEntries map[missingDataKey]*bitset.BitSet,
	btlPolicy pvtdatapolicy.BTLPolicy) ([]*expiryEntry, error) {
	var expiryEntries []*expiryEntry
	mapByExpiringBlk := make(map[uint64]*ExpiryData)
	for _, dataEntry := range dataEntries {
		if err := prepareExpiryEntriesForPresentData(mapByExpiringBlk, dataEntry.key, btlPolicy); err != nil {
			return nil, err
		}
	}

	for missingDataKey := range elgMissingDataEntries {
		if err := prepareExpiryEntriesForMissingData(mapByExpiringBlk, &missingDataKey, btlPolicy); err != nil {
			return nil, err
		}
	}

	for missingDataKey := range inelgMissingDataEntries {
		if err := prepareExpiryEntriesForMissingData(mapByExpiringBlk, &missingDataKey, btlPolicy); err != nil {
			return nil, err
		}
	}

	for expiryBlk, expiryData := range mapByExpiringBlk {
		expiryKey := &expiryKey{expiringBlk: expiryBlk, committingBlk: committingBlk}
		expiryEntries = append(expiryEntries, &expiryEntry{key: expiryKey, value: expiryData})
	}

	return expiryEntries, nil
}


func prepareExpiryEntriesForPresentData(mapByExpiringBlk map[uint64]*ExpiryData, dataKey *dataKey, btlPolicy pvtdatapolicy.BTLPolicy) error {
	expiringBlk, err := btlPolicy.GetExpiringBlock(dataKey.ns, dataKey.coll, dataKey.blkNum)
	if err != nil {
		return err
	}
	if neverExpires(expiringBlk) {
		return nil
	}

	expiryData := getOrCreateExpiryData(mapByExpiringBlk, expiringBlk)

	expiryData.addPresentData(dataKey.ns, dataKey.coll, dataKey.txNum)
	return nil
}

func prepareExpiryEntriesForMissingData(mapByExpiringBlk map[uint64]*ExpiryData, missingKey *missingDataKey, btlPolicy pvtdatapolicy.BTLPolicy) error {
	expiringBlk, err := btlPolicy.GetExpiringBlock(missingKey.ns, missingKey.coll, missingKey.blkNum)
	if err != nil {
		return err
	}
	if neverExpires(expiringBlk) {
		return nil
	}

	expiryData := getOrCreateExpiryData(mapByExpiringBlk, expiringBlk)

	expiryData.addMissingData(missingKey.ns, missingKey.coll)

	return nil
}


func neverExpires(expiringBlkNum uint64) bool {
	return expiringBlkNum == math.MaxUint64
}

func getOrCreateExpiryData(mapByExpiringBlk map[uint64]*ExpiryData, expiringBlk uint64) *ExpiryData {
	expiryData, ok := mapByExpiringBlk[expiringBlk]
	if !ok {
		expiryData = newExpiryData()
		mapByExpiringBlk[expiringBlk] = expiryData
	}
	return expiryData
}

func deriveKeys(expiryEntry *expiryEntry) ([]*dataKey, []*missingDataKey) {
	var dataKeys []*dataKey
	var missingDataKeys []*missingDataKey

	for ns, colls := range expiryEntry.value.Map {
		for coll, txNums := range colls.Map {
			for _, txNum := range txNums.List {
				dataKeys = append(dataKeys,
					&dataKey{
						nsCollBlk: nsCollBlk{
							ns:     ns,
							coll:   coll,
							blkNum: expiryEntry.key.committingBlk,
						},
						txNum: txNum,
					})
			}
		}

		for coll := range colls.MissingDataMap {
			missingDataKeys = append(missingDataKeys,
				&missingDataKey{
					nsCollBlk: nsCollBlk{
						ns:     ns,
						coll:   coll,
						blkNum: expiryEntry.key.committingBlk,
					},
				})
		}
	}

	return dataKeys, missingDataKeys
}

type txPvtdataAssembler struct {
	blockNum, txNum uint64
	txWset          *rwset.TxPvtReadWriteSet
	currentNsWSet   *rwset.NsPvtReadWriteSet
	firstCall       bool
}
