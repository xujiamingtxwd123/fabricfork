package msp

import (
	"github.com/hyperledger/fabric/bccsp"
	"github.com/spf13/viper"
	"sync"
)

var m sync.Mutex
var localMsp MSP

func GetLocalMSP(cryptoProvider bccsp.BCCSP) MSP {
	m.Lock()
	defer m.Unlock()

	if localMsp != nil {
		return localMsp
	}

	localMsp = loadLocalMSP(cryptoProvider)

	return localMsp
}

func loadLocalMSP(bccsp bccsp.BCCSP) MSP {
	// determine the type of MSP (by default, we'll use bccspMSP)
	mspType := viper.GetString("peer.localMspType")
	if mspType == "" {
		mspType = ProviderTypeToString(FABRIC)
	}

	newOpts, found := Options[mspType]
	if !found {
		panic("msp type " + mspType + " unknown")
	}

	mspInst, err := New(newOpts, bccsp)
	if err != nil {
		panic("Failed to initialize local MSP, received err " + err.Error())
	}

	//先不上缓存 TODO xjm
	//switch mspType {
	//case ProviderTypeToString(FABRIC):
	//	mspInst, err = cache.New(mspInst)
	//	if err != nil {
	//		panic("Failed to initialize local MSP, received err " + err.Error())
	//	}
	//default:
	//	panic("msp type " + mspType + " unknown")
	//}

	return mspInst
}
