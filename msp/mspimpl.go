package msp

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"github.com/golang/protobuf/proto"
	msppb "github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
	"math/big"
	"reflect"
	"time"
)

type bccspmsp struct {
	name         string //msp name
	cryptoConfig *msppb.FabricCryptoConfig
	CRL          []*pkix.CertificateList
	//msp 验证参数 保证证书链都在options
	opts                                 *x509.VerifyOptions
	bccsp                                bccsp.BCCSP
	ouIdentifiers                        map[string][][]byte
	rootCerts                            []Identity
	intermediateCerts                    []Identity
	certificationTreeInternalNodesMap    map[string]bool
	signer                               SigningIdentity
	tlsRootCerts                         [][]byte
	tlsIntermediateCerts                 [][]byte
	ouEnforcement                        bool
	clientOU, peerOU, adminOU, ordererOU *OUIdentifier
	admins                               []Identity
	version                              MSPVersion
}

func NewBccspMSP(opts NewOpts, cryptoProvider bccsp.BCCSP) (MSP, error) {
	bm := &bccspmsp{}
	bm.bccsp = cryptoProvider
	bm.version = opts.GetVersion()
	return bm, nil
}

func (msp *bccspmsp) Setup(conf *msppb.MSPConfig) error {
	if conf == nil {
		return errors.New("Setup error: nil conf reference")
	}
	confMsp := &msppb.FabricMSPConfig{}
	err := proto.Unmarshal(conf.Config, confMsp)
	if err != nil {
		return errors.Wrap(err, "failed unmarshalling fabric msp config")
	}
	msp.name = confMsp.Name
	err = msp.preSetupV142(confMsp)
	if err != nil {
		return err
	}
	err = msp.postSetupV142(confMsp)
	if err != nil {
		return err
	}

	return nil
}

func (msp *bccspmsp) hasOURole(id Identity, mspRole msppb.MSPRole_MSPRoleType) error {
	// Check NodeOUs
	if !msp.ouEnforcement {
		return errors.New("NodeOUs not activated. Cannot tell apart identities.")
	}

	switch id := id.(type) {
	// If this identity is of this specific type,
	// this is how I can validate it given the
	// root of trust this MSP has
	case *identity:
		return msp.hasOURoleInternal(id, mspRole)
	default:
		return errors.New("Identity type not recognized")
	}
}

func (msp *bccspmsp) hasOURoleInternal(id *identity, mspRole msppb.MSPRole_MSPRoleType) error {
	var nodeOU *OUIdentifier
	switch mspRole {
	case msppb.MSPRole_CLIENT:
		nodeOU = msp.clientOU
	case msppb.MSPRole_PEER:
		nodeOU = msp.peerOU
	case msppb.MSPRole_ADMIN:
		nodeOU = msp.adminOU
	case msppb.MSPRole_ORDERER:
		nodeOU = msp.ordererOU
	default:
		return errors.New("Invalid MSPRoleType. It must be CLIENT, PEER, ADMIN or ORDERER")
	}

	if nodeOU == nil {
		return errors.Errorf("cannot test for classification, node ou for type [%s], not defined, msp: [%s]", mspRole, msp.name)
	}

	for _, OU := range id.GetOrganizationalUnits() {
		if OU.OrganizationalUnitIdentifier == nodeOU.OrganizationalUnitIdentifier {
			return nil
		}
	}

	return errors.Errorf("The identity does not contain OU [%s], MSP: [%s]", mspRole, msp.name)
}

func (msp *bccspmsp) postSetupV142(conf *msppb.FabricMSPConfig) error {
	// Check for OU enforcement
	if !msp.ouEnforcement {
		// No enforcement required. Call post setup as per V1
		return msp.postSetupV1(conf)
	}

	// Check that admins are clients or admins
	for i, admin := range msp.admins {
		err1 := msp.hasOURole(admin, msppb.MSPRole_CLIENT)
		err2 := msp.hasOURole(admin, msppb.MSPRole_ADMIN)
		if err1 != nil && err2 != nil {
			return errors.Errorf("admin %d is invalid [%s,%s]", i, err1, err2)
		}
	}

	return nil
}

func (msp *bccspmsp) postSetupV1(conf *msppb.FabricMSPConfig) error {
	// make sure that admins are valid members as well
	// this way, when we validate an admin MSP principal
	// we can simply check for exact match of certs
	for i, admin := range msp.admins {
		err := admin.Validate()
		if err != nil {
			return errors.WithMessagef(err, "admin %d is invalid", i)
		}
	}

	return nil
}

func (msp *bccspmsp) DeserializeIdentity(serializedIdentity []byte) (Identity, error) {
	panic("implement me")
}

func (msp *bccspmsp) IsWellFormed(identity *msppb.SerializedIdentity) error {
	panic("implement me")
}

func (msp *bccspmsp) GetVersion() MSPVersion {
	return msp.version
}

func (msp *bccspmsp) GetType() ProviderType {
	return FABRIC
}

func (msp *bccspmsp) GetIdentifier() (string, error) {
	return msp.name, nil
}

func (msp *bccspmsp) GetSigningIdentity(identifier *IdentityIdentifier) (SigningIdentity, error) {
	//TODO xjm
	return nil, nil
}

func (msp *bccspmsp) GetDefaultSigningIdentity() (SigningIdentity, error) {
	if msp.signer == nil {
		return nil, errors.New("this MSP does not possess a valid default signing identity")
	}

	return msp.signer, nil
}

func (msp *bccspmsp) GetTLSRootCerts() [][]byte {
	return msp.tlsRootCerts
}

func (msp *bccspmsp) GetTLSIntermediateCerts() [][]byte {
	return msp.tlsIntermediateCerts
}

func (msp *bccspmsp) Validate(id Identity) error {
	switch id := id.(type) {
	// If this identity is of this specific type,
	// this is how I can validate it given the
	// root of trust this MSP has
	case *identity:
		return msp.validateIdentity(id)
	default:
		return errors.New("identity type not recognized")
	}
}

func (msp *bccspmsp) validateIdentity(id *identity) error {
	id.validationMutex.Lock()
	defer id.validationMutex.Unlock()

	if id.validated {
		return id.validationErr
	}
	id.validated = true

	//获得证书链
	validationChain, err := msp.getCertificationChainForBCCSPIdentity(id)
	if err != nil {
		id.validationErr = errors.WithMessage(err, "could not obtain certification chain")
		return id.validationErr
	}

	//验证证书链关系
	err = msp.validateIdentityAgainstChain(id, validationChain)
	if err != nil {
		id.validationErr = errors.WithMessage(err, "could not validate identity against certification chain")
		return id.validationErr
	}

	//验证OU关系
	err = msp.validateIdentityOUsV142(id)
	if err != nil {
		id.validationErr = errors.WithMessage(err, "could not validate identity's OUs")
		return id.validationErr
	}

	return nil
}

func (msp *bccspmsp) getValidityOptsForCert(cert *x509.Certificate) x509.VerifyOptions {
	// First copy the opts to override the CurrentTime field
	// in order to make the certificate passing the expiration test
	// independently from the real local current time.
	// This is a temporary workaround for FAB-3678

	var tempOpts x509.VerifyOptions
	tempOpts.Roots = msp.opts.Roots
	tempOpts.DNSName = msp.opts.DNSName
	tempOpts.Intermediates = msp.opts.Intermediates
	tempOpts.KeyUsages = msp.opts.KeyUsages
	tempOpts.CurrentTime = cert.NotBefore.Add(time.Second)

	return tempOpts
}

func (msp *bccspmsp) getCertificationChainForBCCSPIdentity(id *identity) ([]*x509.Certificate, error) {
	if id == nil {
		return nil, errors.New("Invalid bccsp identity. Must be different from nil.")
	}

	// we expect to have a valid VerifyOptions instance
	if msp.opts == nil {
		return nil, errors.New("Invalid msp instance")
	}

	// CAs cannot be directly used as identities..
	if id.cert.IsCA {
		return nil, errors.New("An X509 certificate with Basic Constraint: " +
			"Certificate Authority equals true cannot be used as an identity")
	}

	return msp.getValidationChain(id.cert, false)
}

func (msp *bccspmsp) getValidationChain(cert *x509.Certificate, isIntermediateChain bool) ([]*x509.Certificate, error) {
	validationChain, err := msp.getUniqueValidationChain(cert, msp.getValidityOptsForCert(cert))
	if err != nil {
		return nil, errors.WithMessage(err, "failed getting validation chain")
	}

	// we expect a chain of length at least 2
	if len(validationChain) < 2 {
		return nil, errors.Errorf("expected a chain of length at least 2, got %d", len(validationChain))
	}

	//TODO xjm isIntermediateChain 没有使用
	return validationChain, nil
}

func (msp *bccspmsp) getUniqueValidationChain(cert *x509.Certificate, opts x509.VerifyOptions) ([]*x509.Certificate, error) {
	// ask golang to validate the cert for us based on the options that we've built at setup time
	if msp.opts == nil {
		return nil, errors.New("the supplied identity has no verify options")
	}
	validationChains, err := cert.Verify(opts)
	if err != nil {
		return nil, errors.WithMessage(err, "the supplied identity is not valid")
	}

	// we only support a single validation chain;
	// if there's more than one then there might
	// be unclarity about who owns the identity
	if len(validationChains) != 1 {
		return nil, errors.Errorf("this MSP only supports a single validation chain, got %d", len(validationChains))
	}

	return validationChains[0], nil
}

func (msp *bccspmsp) validateIdentityAgainstChain(id *identity, validationChain []*x509.Certificate) error {
	return msp.validateCertAgainstChain(id.cert, validationChain)
}

func getSubjectKeyIdentifierFromCert(cert *x509.Certificate) ([]byte, error) {
	var SKI []byte

	for _, ext := range cert.Extensions {
		// Subject Key Identifier is identified by the following ASN.1 tag
		// subjectKeyIdentifier (2 5 29 14) (see https://tools.ietf.org/html/rfc3280.html)
		if reflect.DeepEqual(ext.Id, asn1.ObjectIdentifier{2, 5, 29, 14}) {
			_, err := asn1.Unmarshal(ext.Value, &SKI)
			if err != nil {
				return nil, errors.Wrap(err, "failed to unmarshal Subject Key Identifier")
			}

			return SKI, nil
		}
	}

	return nil, errors.New("subjectKeyIdentifier not found in certificate")
}

type authorityKeyIdentifier struct {
	KeyIdentifier             []byte  `asn1:"optional,tag:0"`
	AuthorityCertIssuer       []byte  `asn1:"optional,tag:1"`
	AuthorityCertSerialNumber big.Int `asn1:"optional,tag:2"`
}

func getAuthorityKeyIdentifierFromCrl(crl *pkix.CertificateList) ([]byte, error) {
	aki := authorityKeyIdentifier{}

	for _, ext := range crl.TBSCertList.Extensions {
		// Authority Key Identifier is identified by the following ASN.1 tag
		// authorityKeyIdentifier (2 5 29 35) (see https://tools.ietf.org/html/rfc3280.html)
		if reflect.DeepEqual(ext.Id, asn1.ObjectIdentifier{2, 5, 29, 35}) {
			_, err := asn1.Unmarshal(ext.Value, &aki)
			if err != nil {
				return nil, errors.Wrap(err, "failed to unmarshal AKI")
			}

			return aki.KeyIdentifier, nil
		}
	}

	return nil, errors.New("authorityKeyIdentifier not found in certificate")
}

func (msp *bccspmsp) validateCertAgainstChain(cert *x509.Certificate, validationChain []*x509.Certificate) error {
	SKI, err := getSubjectKeyIdentifierFromCert(validationChain[1])
	if err != nil {
		return errors.WithMessage(err, "could not obtain Subject Key Identifier for signer cert")
	}
	for _, crl := range msp.CRL {
		aki, err := getAuthorityKeyIdentifierFromCrl(crl)
		if err != nil {
			return errors.WithMessage(err, "could not obtain Authority Key Identifier for crl")
		}

		// check if the SKI of the cert that signed us matches the AKI of any of the CRLs
		if bytes.Equal(aki, SKI) {
			for _, rc := range crl.TBSCertList.RevokedCertificates {
				if rc.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					// We have found a CRL whose AKI matches the SKI of
					// the CA (root or intermediate) that signed the
					// certificate that is under validation. As a
					// precaution, we verify that said CA is also the
					// signer of this CRL.
					err = validationChain[1].CheckCRLSignature(crl)
					if err != nil {
						// the CA cert that signed the certificate
						// that is under validation did not sign the
						// candidate CRL - skip
						continue
					}

					// A CRL also includes a time of revocation so that
					// the CA can say "this cert is to be revoked starting
					// from this time"; however here we just assume that
					// revocation applies instantaneously from the time
					// the MSP config is committed and used so we will not
					// make use of that field
					return errors.New("The certificate has been revoked")
				}
			}
		}
	}

	return nil
}

func (msp *bccspmsp) validateIdentityOUsV1(id *identity) error {
	if len(msp.ouIdentifiers) > 0 {
		found := false

		for _, OU := range id.GetOrganizationalUnits() {
			certificationIDs, exists := msp.ouIdentifiers[OU.OrganizationalUnitIdentifier]

			if exists {
				for _, certificationID := range certificationIDs {
					if bytes.Equal(certificationID, OU.CertifiersIdentifier) {
						found = true
						break
					}
				}
			}
		}

		if !found {
			if len(id.GetOrganizationalUnits()) == 0 {
				return errors.New("the identity certificate does not contain an Organizational Unit (OU)")
			}
			return errors.Errorf("none of the identity's organizational units %s are in MSP %s", msp.name)
		}
	}

	return nil
}

type OUIDs []*OUIdentifier

func (o OUIDs) String() string {
	var res []string
	for _, id := range o {
		res = append(res, fmt.Sprintf("%s(%X)", id.OrganizationalUnitIdentifier, id.CertifiersIdentifier[0:8]))
	}

	return fmt.Sprintf("%s", res)
}

func (msp *bccspmsp) validateIdentityOUsV142(id *identity) error {
	err := msp.validateIdentityOUsV1(id)
	if err != nil {
		return err
	}

	// -- Check for OU enforcement
	if !msp.ouEnforcement {
		// No enforcement required
		return nil
	}

	// Make sure that the identity has only one of the special OUs
	// used to tell apart clients, peers and admins.
	counter := 0
	validOUs := make(map[string]*OUIdentifier)
	if msp.clientOU != nil {
		validOUs[msp.clientOU.OrganizationalUnitIdentifier] = msp.clientOU
	}
	if msp.peerOU != nil {
		validOUs[msp.peerOU.OrganizationalUnitIdentifier] = msp.peerOU
	}
	if msp.adminOU != nil {
		validOUs[msp.adminOU.OrganizationalUnitIdentifier] = msp.adminOU
	}
	if msp.ordererOU != nil {
		validOUs[msp.ordererOU.OrganizationalUnitIdentifier] = msp.ordererOU
	}

	for _, OU := range id.GetOrganizationalUnits() {
		// Is OU.OrganizationalUnitIdentifier one of the special OUs?
		nodeOU := validOUs[OU.OrganizationalUnitIdentifier]
		if nodeOU == nil {
			continue
		}

		// Yes. Then, enforce the certifiers identifier in this is specified.
		// If is not specified, it means that any certification path is fine.
		if len(nodeOU.CertifiersIdentifier) != 0 && !bytes.Equal(nodeOU.CertifiersIdentifier, OU.CertifiersIdentifier) {
			return errors.Errorf("certifiersIdentifier does not match: %s, MSP: [%s]", OUIDs(id.GetOrganizationalUnits()), msp.name)
		}
		counter++
		if counter > 1 {
			break
		}
	}
	if counter != 1 {
		return errors.Errorf("the identity must be a client, a peer, an orderer or an admin identity to be valid, not a combination of them. OUs: %s, MSP: [%s]", OUIDs(id.GetOrganizationalUnits()), msp.name)
	}

	return nil
}
func (msp *bccspmsp) SatisfiesPrincipal(id Identity, principal *msppb.MSPPrincipal) error {
	panic("implement me")
}
