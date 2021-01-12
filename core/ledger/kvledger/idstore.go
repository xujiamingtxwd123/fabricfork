package kvledger

import (
	"bytes"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/pkg/errors"
	"github.com/syndtr/goleveldb/leveldb"

	"fabricfork/common/ledger/dataformat"
	"fabricfork/common/ledger/util/leveldbhelper"
	"fabricfork/core/ledger/kvledger/msgs"
	"fabricfork/protoutil"
)

type idStore struct {
	db     *leveldbhelper.DB
	dbPath string
}

//生成idStore
func openIDStore(path string) (s *idStore, e error) {
	db := leveldbhelper.CreateDB(&leveldbhelper.Conf{DBPath: path})
	db.Open()
	defer func() {
		if e != nil {
			db.Close()
		}
	}()
	emptyDB, err := db.IsEmpty()
	if err != nil {
		return nil, err
	}

	expectedFormatBytes := []byte(dataformat.CurrentFormat)
	if emptyDB {
		// add format key to a new db
		err := db.Put(formatKey, expectedFormatBytes, true)
		if err != nil {
			return nil, err
		}
		return &idStore{db, path}, nil
	}
	// verify the format is current for an existing db
	format, err := db.Get(formatKey)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(format, expectedFormatBytes) {
		logger.Errorf("The db at path [%s] contains data in unexpected format. expected data format = [%s] (%#v), data format = [%s] (%#v).",
			path, dataformat.CurrentFormat, expectedFormatBytes, format, format)
		return nil, &dataformat.ErrFormatMismatch{
			ExpectedFormat: dataformat.CurrentFormat,
			Format:         string(format),
			DBInfo:         fmt.Sprintf("leveldb for channel-IDs at [%s]", path),
		}
	}
	return &idStore{db, path}, nil
}

//idStore 服务能力
func (s *idStore) encodeLedgerKey(ledgerID string, prefix []byte) []byte {
	return append(prefix, []byte(ledgerID)...)
}

func (s *idStore) decodeLedgerID(key []byte, prefix []byte) string {
	return string(key[len(prefix):])
}

/*
	存储ledgerID的元信息，包括创世区块、ACTIVE状态
*/
func (s *idStore) createLedgerID(ledgerID string, gb *common.Block) error {
	ledgerIDKey := s.encodeLedgerKey(ledgerID, ledgerKeyPrefix)
	val, err := s.db.Get(ledgerIDKey)
	if err != nil {
		return err
	}
	if val != nil {
		return ErrLedgerIDExists
	}
	if val, err = proto.Marshal(gb); err != nil {
		return err
	}
	metadata, err := protoutil.Marshal(&msgs.LedgerMetadata{Status: msgs.Status_ACTIVE})
	batch := &leveldb.Batch{}
	batch.Put(ledgerIDKey, val)
	metadataKey := s.encodeLedgerKey(ledgerID, metadataKeyPrefix)
	batch.Put(metadataKey, metadata)
	batch.Delete(underConstructionLedgerKey)
	return s.db.WriteBatch(batch, true)
}

func (s *idStore) updateLedgerStatus(ledgerID string, newStatus msgs.Status) error {
	metadata, err := s.getLedgerMetadata(ledgerID)
	if err != nil {
		return err
	}
	if metadata == nil {
		logger.Errorf("LedgerID [%s] does not exist", ledgerID)
		return ErrNonExistingLedgerID
	}

	if metadata.Status == newStatus {
		logger.Infof("Ledger [%s] is already in [%s] status, nothing to do", ledgerID, newStatus)
		return nil
	}
	metadata.Status = newStatus
	metadataBytes, err := proto.Marshal(metadata)
	if err != nil {
		logger.Errorf("Error marshalling ledger metadata: %s", err)
		return errors.Wrapf(err, "error marshalling ledger metadata")
	}
	logger.Infof("Updating ledger [%s] status to [%s]", ledgerID, newStatus)
	key := s.encodeLedgerKey(ledgerID, metadataKeyPrefix)
	return s.db.Put(key, metadataBytes, true)

}

func (s *idStore) getLedgerMetadata(ledgerID string) (*msgs.LedgerMetadata, error) {
	val, err := s.db.Get(s.encodeLedgerKey(ledgerID, metadataKeyPrefix))
	if val == nil || err != nil {
		return nil, err
	}
	metadata := &msgs.LedgerMetadata{}
	if err := proto.Unmarshal(val, metadata); err != nil {
		logger.Errorf("Error unmarshalling ledger metadata: %s", err)
		return nil, errors.Wrapf(err, "error unmarshalling ledger metadata")
	}
	return metadata, nil
}

func (s *idStore) ledgerIDExists(ledgerID string) (bool, error) {
	key := s.encodeLedgerKey(ledgerID, ledgerKeyPrefix)
	val, err := s.db.Get(key)
	if err != nil {
		return false, err
	}
	return val != nil, nil
}

func (s *idStore) ledgerIDActive(ledgerID string) (bool, bool, error) {
	metadata, err := s.getLedgerMetadata(ledgerID)
	if metadata == nil || err != nil {
		return false, false, err
	}
	return metadata.Status == msgs.Status_ACTIVE, true, nil
}

func (s *idStore) getActiveLedgerIDs() ([]string, error) {
	var ids []string
	itr := s.db.GetIterator(metadataKeyPrefix, metadataKeyStop)
	defer itr.Release()
	for itr.Error() == nil && itr.Next() {
		metadata := &msgs.LedgerMetadata{}
		if err := proto.Unmarshal(itr.Value(), metadata); err != nil {
			logger.Errorf("Error unmarshalling ledger metadata: %s", err)
			return nil, errors.Wrapf(err, "error unmarshalling ledger metadata")
		}
		if metadata.Status == msgs.Status_ACTIVE {
			id := s.decodeLedgerID(itr.Key(), metadataKeyPrefix)
			ids = append(ids, id)
		}
	}
	if err := itr.Error(); err != nil {
		logger.Errorf("Error getting ledger ids from idStore: %s", err)
		return nil, errors.Wrapf(err, "error getting ledger ids from idStore")
	}
	return ids, nil
}

func (s *idStore) close() {
	s.db.Close()
}
