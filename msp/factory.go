package msp

import (
	"errors"
	"github.com/hyperledger/fabric/bccsp"
)

type MSPVersion int

const (
	MSPv1_0 = iota
	MSPv1_1
	MSPv1_3
	MSPv1_4_3
)

type NewOpts interface {
	// GetVersion returns the MSP's version to be instantiated
	GetVersion() MSPVersion
	GetMspType() ProviderType
}

type NewBaseOpts struct {
	version MSPVersion
	mspType ProviderType
}


func (opts *NewBaseOpts) GetVersion() MSPVersion {
	return opts.version
}

func (opts *NewBaseOpts) GetMspType() ProviderType {
	return opts.mspType
}

func New(opts NewOpts, cryptoProvider bccsp.BCCSP) (MSP, error) {
	if opts.GetVersion() != MSPv1_4_3 || opts.GetMspType() != FABRIC{
		return nil, errors.New("now only support other msp type, except 1.4.3")
	}
	return NewBccspMSP(opts, cryptoProvider)

}





