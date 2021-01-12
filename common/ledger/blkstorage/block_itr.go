package blkstorage

import (
	"sync"

	"fabricfork/common/ledger"
)

type blocksItr struct {
	mgr                  *blockfileMgr
	maxBlockNumAvailable uint64
	blockNumToRetrieve   uint64
	stream               *blockStream
	closeMarker          bool
	closeMarkerLock      *sync.Mutex
}

func newBlockItr(mgr *blockfileMgr, startBlockNum uint64) *blocksItr {
	mgr.blkfilesInfoCond.L.Lock()
	defer mgr.blkfilesInfoCond.L.Unlock()
	return &blocksItr{mgr, mgr.blockfilesInfo.lastPersistedBlock, startBlockNum, nil, false, &sync.Mutex{}}
}

func (itr *blocksItr) Next() (ledger.QueryResult, error) {
	//如果请求的block itr 还没有该区块 需要等待
	if itr.maxBlockNumAvailable < itr.blockNumToRetrieve {
		itr.maxBlockNumAvailable = itr.waitForBlock(itr.blockNumToRetrieve)
	}

	itr.closeMarkerLock.Lock()
	defer itr.closeMarkerLock.Unlock()
	if itr.closeMarker {
		return nil, nil
	}

	if itr.stream == nil {
		if err := itr.initStream(); err != nil {
			return nil, err
		}
	}
	nextBlockBytes, err := itr.stream.nextBlockBytes()
	if err != nil {
		return nil, err
	}
	itr.blockNumToRetrieve++
	return deserializeBlock(nextBlockBytes)
}

func (itr *blocksItr) initStream() error {
	var lp *fileLocPointer
	var err error
	if lp, err = itr.mgr.index.getBlockLocByBlockNum(itr.blockNumToRetrieve); err != nil {
		return err
	}
	if itr.stream, err = newBlockStream(itr.mgr.rootDir, lp.fileSuffixNum, int64(lp.offset), -1); err != nil {
		return err
	}
	return nil
}

func (itr *blocksItr) waitForBlock(blockNum uint64) uint64 {
	itr.mgr.blkfilesInfoCond.L.Lock()
	defer itr.mgr.blkfilesInfoCond.L.Unlock()
	for itr.mgr.blockfilesInfo.lastPersistedBlock < blockNum && !itr.shouldClose() {
		itr.mgr.blkfilesInfoCond.Wait()
	}
	return itr.mgr.blockfilesInfo.lastPersistedBlock
}

func (itr *blocksItr) shouldClose() bool {
	itr.closeMarkerLock.Lock()
	defer itr.closeMarkerLock.Unlock()
	return itr.closeMarker
}

func (itr *blocksItr) Close() {

}
