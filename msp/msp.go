package msp

import (
	"github.com/hyperledger/fabric-protos-go/msp"
	"time"
)

type ProviderType int

const (
	FABRIC ProviderType = iota
)

var mspTypeStrings = map[ProviderType]string{
	FABRIC: "bccsp",
}

// ProviderTypeToString returns a string that represents the ProviderType integer
func ProviderTypeToString(id ProviderType) string {
	if res, found := mspTypeStrings[id]; found {
		return res
	}

	return ""
}
var Options = map[string]NewOpts{
	ProviderTypeToString(FABRIC): &NewBaseOpts{version: MSPv1_4_3, mspType: FABRIC},
}

type IdentityIdentifier struct {

	// The identifier of the associated membership service provider
	Mspid string

	// The identifier for an identity within a provider
	Id string
}

type OUIdentifier struct {
	// CertifiersIdentifier is the hash of certificates chain of trust
	// related to this organizational unit
	CertifiersIdentifier []byte
	// OrganizationUnitIdentifier defines the organizational unit under the
	// MSP identified with MSPIdentifier
	OrganizationalUnitIdentifier string
}

type SigningIdentity interface {

	// Extends Identity
	Identity

	// Sign the message
	Sign(msg []byte) ([]byte, error)

	// GetPublicVersion returns the public parts of this identity
	GetPublicVersion() Identity
}

type Identity interface {

	// ExpiresAt returns the time at which the Identity expires.
	// If the returned time is the zero value, it implies
	// the Identity does not expire, or that its expiration
	// time is unknown
	ExpiresAt() time.Time

	// GetIdentifier returns the identifier of that identity
	GetIdentifier() *IdentityIdentifier

	// GetMSPIdentifier returns the MSP Id for this instance
	GetMSPIdentifier() string

	// Validate uses the rules that govern this identity to validate it.
	// E.g., if it is a fabric TCert implemented as identity, validate
	// will check the TCert signature against the assumed root certificate
	// authority.
	Validate() error

	// GetOrganizationalUnits returns zero or more organization units or
	// divisions this identity is related to as long as this is public
	// information. Certain MSP implementations may use attributes
	// that are publicly associated to this identity, or the identifier of
	// the root certificate authority that has provided signatures on this
	// certificate.
	// Examples:
	//  - if the identity is an x.509 certificate, this function returns one
	//    or more string which is encoded in the Subject's Distinguished Name
	//    of the type OU
	// TODO: For X.509 based identities, check if we need a dedicated type
	//       for OU where the Certificate OU is properly namespaced by the
	//       signer's identity
	GetOrganizationalUnits() []*OUIdentifier

	// Anonymous returns true if this is an anonymous identity, false otherwise
	Anonymous() bool

	// Verify a signature over some message using this identity as reference
	Verify(msg []byte, sig []byte) error

	// Serialize converts an identity to bytes
	Serialize() ([]byte, error)

	// SatisfiesPrincipal checks whether this instance matches
	// the description supplied in MSPPrincipal. The check may
	// involve a byte-by-byte comparison (if the principal is
	// a serialized identity) or may require MSP validation
	SatisfiesPrincipal(principal *msp.MSPPrincipal) error
}


type IdentityDeserializer interface {
	// DeserializeIdentity deserializes an identity.
	// Deserialization will fail if the identity is associated to
	// an msp that is different from this one that is performing
	// the deserialization.
	DeserializeIdentity(serializedIdentity []byte) (Identity, error)

	// IsWellFormed checks if the given identity can be deserialized into its provider-specific form
	IsWellFormed(identity *msp.SerializedIdentity) error
}

type MSP interface {

	// IdentityDeserializer interface needs to be implemented by MSP
	IdentityDeserializer

	// Setup the MSP instance according to configuration information
	Setup(config *msp.MSPConfig) error

	// GetVersion returns the version of this MSP
	GetVersion() MSPVersion

	// GetType returns the provider type
	GetType() ProviderType

	// GetIdentifier returns the provider identifier
	GetIdentifier() (string, error)

	// GetSigningIdentity returns a signing identity corresponding to the provided identifier
	GetSigningIdentity(identifier *IdentityIdentifier) (SigningIdentity, error)

	// GetDefaultSigningIdentity returns the default signing identity
	GetDefaultSigningIdentity() (SigningIdentity, error)

	// GetTLSRootCerts returns the TLS root certificates for this MSP
	GetTLSRootCerts() [][]byte

	// GetTLSIntermediateCerts returns the TLS intermediate root certificates for this MSP
	GetTLSIntermediateCerts() [][]byte

	// Validate checks whether the supplied identity is valid
	Validate(id Identity) error

	// SatisfiesPrincipal checks whether the identity matches
	// the description supplied in MSPPrincipal. The check may
	// involve a byte-by-byte comparison (if the principal is
	// a serialized identity) or may require MSP validation
	SatisfiesPrincipal(id Identity, principal *msp.MSPPrincipal) error
}