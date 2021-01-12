package pvtdatastorage

import (
	"bytes"
	"encoding/binary"
	"fabricfork/core/ledger/internal/version"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/ledger/rwset"
	"github.com/pkg/errors"
	"github.com/willf/bitset"
	"math"
)

var (
	pendingCommitKey                 = []byte{0}
	lastCommittedBlkkey              = []byte{1}
	pvtDataKeyPrefix                 = []byte{2}
	expiryKeyPrefix                  = []byte{3}
	elgPrioritizedMissingDataGroup   = []byte{4}
	inelgMissingDataGroup            = []byte{5}
	collElgKeyPrefix                 = []byte{6}
	elgDeprioritizedMissingDataGroup = []byte{8}

	nilByte    = byte(0)
)

func encodeCollElgKey(blkNum uint64) []byte {
	return append(collElgKeyPrefix, encodeReverseOrderVarUint64(blkNum)...)
}

func decodeCollElgKey(b []byte) uint64 {
	blkNum, _ := decodeReverseOrderVarUint64(b[1:])
	return blkNum
}

func encodeReverseOrderVarUint64(number uint64) []byte {
	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, math.MaxUint64-number)
	numFFBytes := 0
	for _, b := range bytes {
		if b != 0xff {
			break
		}
		numFFBytes++
	}
	size := 8 - numFFBytes
	encodedBytes := make([]byte, size+1)
	encodedBytes[0] = proto.EncodeVarint(uint64(numFFBytes))[0]
	copy(encodedBytes[1:], bytes[numFFBytes:])
	return encodedBytes
}

func decodeReverseOrderVarUint64(bytes []byte) (uint64, int) {
	s, _ := proto.DecodeVarint(bytes)
	numFFBytes := int(s)
	decodedBytes := make([]byte, 8)
	realBytesNum := 8 - numFFBytes
	copy(decodedBytes[numFFBytes:], bytes[1:realBytesNum+1])
	numBytesConsumed := realBytesNum + 1
	for i := 0; i < numFFBytes; i++ {
		decodedBytes[i] = 0xff
	}
	return (math.MaxUint64 - binary.BigEndian.Uint64(decodedBytes)), numBytesConsumed
}

func decodeCollElgVal(b []byte) (*CollElgInfo, error) {
	m := &CollElgInfo{}
	if err := proto.Unmarshal(b, m); err != nil {
		return nil, errors.WithStack(err)
	}
	return m, nil
}

type nsCollBlk struct {
	ns, coll string
	blkNum   uint64
}

type dataKey struct {
	nsCollBlk
	txNum uint64
}

type missingDataKey struct {
	nsCollBlk
}

func encodeElgDeprioMissingDataKey(key *missingDataKey) []byte {
	encKey := append(elgDeprioritizedMissingDataGroup, encodeReverseOrderVarUint64(key.blkNum)...)
	encKey = append(encKey, []byte(key.ns)...)
	encKey = append(encKey, nilByte)
	return append(encKey, []byte(key.coll)...)
}

func decodeElgMissingDataKey(keyBytes []byte) *missingDataKey {
	key := &missingDataKey{nsCollBlk: nsCollBlk{}}
	blkNum, numBytesConsumed := decodeReverseOrderVarUint64(keyBytes[1:])
	splittedKey := bytes.Split(keyBytes[numBytesConsumed+1:], []byte{nilByte})
	key.ns = string(splittedKey[0])
	key.coll = string(splittedKey[1])
	key.blkNum = blkNum
	return key
}

func encodeInelgMissingDataKey(key *missingDataKey) []byte {
	encKey := append(inelgMissingDataGroup, []byte(key.ns)...)
	encKey = append(encKey, nilByte)
	encKey = append(encKey, []byte(key.coll)...)
	encKey = append(encKey, nilByte)
	return append(encKey, []byte(encodeReverseOrderVarUint64(key.blkNum))...)
}

func decodeInelgMissingDataKey(keyBytes []byte) *missingDataKey {
	key := &missingDataKey{nsCollBlk: nsCollBlk{}}
	splittedKey := bytes.SplitN(keyBytes[1:], []byte{nilByte}, 3) //encoded bytes for blknum may contain empty bytes
	key.ns = string(splittedKey[0])
	key.coll = string(splittedKey[1])
	key.blkNum, _ = decodeReverseOrderVarUint64(splittedKey[2])
	return key
}

func encodeElgPrioMissingDataKey(key *missingDataKey) []byte {
	// When missing pvtData reconciler asks for missing data info,
	// it is necessary to pass the missing pvtdata info associated with
	// the most recent block so that missing pvtdata in the state db can
	// be fixed sooner to reduce the "private data matching public hash version
	// is not available" error during endorserments. In order to give priority
	// to missing pvtData in the most recent block, we use reverse order
	// preserving encoding for the missing data key. This simplifies the
	// implementation of GetMissingPvtDataInfoForMostRecentBlocks().
	encKey := append(elgPrioritizedMissingDataGroup, encodeReverseOrderVarUint64(key.blkNum)...)
	encKey = append(encKey, []byte(key.ns)...)
	encKey = append(encKey, nilByte)
	return append(encKey, []byte(key.coll)...)
}

func encodeMissingDataValue(bitmap *bitset.BitSet) ([]byte, error) {
	return bitmap.MarshalBinary()
}

func createRangeScanKeysForInelgMissingData(maxBlkNum uint64, ns, coll string) ([]byte, []byte) {
	startKey := encodeInelgMissingDataKey(
		&missingDataKey{
			nsCollBlk: nsCollBlk{
				ns:     ns,
				coll:   coll,
				blkNum: maxBlkNum,
			},
		},
	)
	endKey := encodeInelgMissingDataKey(
		&missingDataKey{
			nsCollBlk: nsCollBlk{
				ns:     ns,
				coll:   coll,
				blkNum: 0,
			},
		},
	)

	return startKey, endKey
}

func encodeDataKey(key *dataKey) []byte {
	dataKeyBytes := append(pvtDataKeyPrefix, version.NewHeight(key.blkNum, key.txNum).ToBytes()...)
	dataKeyBytes = append(dataKeyBytes, []byte(key.ns)...)
	dataKeyBytes = append(dataKeyBytes, nilByte)
	return append(dataKeyBytes, []byte(key.coll)...)
}

func encodeDataValue(collData *rwset.CollectionPvtReadWriteSet) ([]byte, error) {
	return proto.Marshal(collData)
}

func encodeExpiryKey(expiryKey *expiryKey) []byte {
	// reusing version encoding scheme here
	return append(expiryKeyPrefix, version.NewHeight(expiryKey.expiringBlk, expiryKey.committingBlk).ToBytes()...)
}

func encodeExpiryValue(expiryData *ExpiryData) ([]byte, error) {
	return proto.Marshal(expiryData)
}

func decodeExpiryKey(expiryKeyBytes []byte) (*expiryKey, error) {
	height, _, err := version.NewHeightFromBytes(expiryKeyBytes[1:])
	if err != nil {
		return nil, err
	}
	return &expiryKey{expiringBlk: height.BlockNum, committingBlk: height.TxNum}, nil
}

func decodeExpiryValue(expiryValueBytes []byte) (*ExpiryData, error) {
	expiryData := &ExpiryData{}
	err := proto.Unmarshal(expiryValueBytes, expiryData)
	return expiryData, err
}

func encodeLastCommittedBlockVal(blockNum uint64) []byte {
	return proto.EncodeVarint(blockNum)
}

func decodeLastCommittedBlockVal(blockNumBytes []byte) uint64 {
	s, _ := proto.DecodeVarint(blockNumBytes)
	return s
}

func getExpiryKeysForRangeScan(minBlkNum, maxBlkNum uint64) ([]byte, []byte) {
	startKey := append(expiryKeyPrefix, version.NewHeight(minBlkNum, 0).ToBytes()...)
	endKey := append(expiryKeyPrefix, version.NewHeight(maxBlkNum+1, 0).ToBytes()...)
	return startKey, endKey
}

func getDataKeysForRangeScanByBlockNum(blockNum uint64) ([]byte, []byte) {
	startKey := append(pvtDataKeyPrefix, version.NewHeight(blockNum, 0).ToBytes()...)
	endKey := append(pvtDataKeyPrefix, version.NewHeight(blockNum+1, 0).ToBytes()...)
	return startKey, endKey
}