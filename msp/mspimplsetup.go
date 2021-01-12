package msp

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	msppb "github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/signer"
	"github.com/pkg/errors"
	"time"
)

func (msp *bccspmsp) preSetupV142(conf *msppb.FabricMSPConfig) error {
	// setup crypto config
	if err := msp.setupCrypto(conf); err != nil {
		return err
	}

	// Setup CAs
	if err := msp.setupCAs(conf); err != nil {
		return err
	}

	// Setup CRLs
	if err := msp.setupCRLs(conf); err != nil {
		return err
	}

	// Finalize setup of the CAs
	if err := msp.finalizeSetupCAs(); err != nil {
		return err
	}

	// setup the signer (if present)
	if err := msp.setupSigningIdentity(conf); err != nil {
		return err
	}

	// setup TLS CAs
	if err := msp.setupTLSCAs(conf); err != nil {
		return err
	}

	// setup the OUs
	if err := msp.setupOUs(conf); err != nil {
		return err
	}

	// setup NodeOUs
	if err := msp.setupNodeOUsV142(conf); err != nil {
		return err
	}

	// Setup Admins
	if err := msp.setupAdminsPreV142(conf); err != nil {
		return err
	}

	return nil
}

func (msp *bccspmsp) getCertFromPem(idBytes []byte) (*x509.Certificate, error) {
	if idBytes == nil {
		return nil, errors.New("getCertFromPem error: nil idBytes")
	}

	// Decode the pem bytes
	pemCert, _ := pem.Decode(idBytes)
	if pemCert == nil {
		return nil, errors.Errorf("getCertFromPem error: could not decode pem bytes [%v]", idBytes)
	}

	// get a cert
	var cert *x509.Certificate
	cert, err := x509.ParseCertificate(pemCert.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "getCertFromPem error: failed to parse x509 cert")
	}

	return cert, nil
}

func (msp *bccspmsp) getIdentityFromConf(idBytes []byte) (Identity, bccsp.Key, error) {
	cert, err := msp.getCertFromPem(idBytes)
	if err != nil {
		return nil, nil, err
	}
	certPubK, err := msp.bccsp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	if err != nil {
		return nil, nil, err
	}
	mspId, err := newIdentity(cert, certPubK, msp)
	if err != nil {
		return nil, nil, err
	}

	return mspId, certPubK, nil
}

func (msp *bccspmsp) setupCrypto(conf *msppb.FabricMSPConfig) error {
	msp.cryptoConfig = conf.CryptoConfig
	if msp.cryptoConfig == nil {
		// Move to defaults
		msp.cryptoConfig = &msppb.FabricCryptoConfig{
			SignatureHashFamily:            bccsp.SHA2,
			IdentityIdentifierHashFunction: bccsp.SHA256,
		}
	}
	if msp.cryptoConfig.SignatureHashFamily == "" {
		msp.cryptoConfig.SignatureHashFamily = bccsp.SHA2
	}
	if msp.cryptoConfig.IdentityIdentifierHashFunction == "" {
		msp.cryptoConfig.IdentityIdentifierHashFunction = bccsp.SHA256
	}

	return nil
}

func (msp *bccspmsp) setupCRLs(conf *msppb.FabricMSPConfig) error {
	// setup the CRL (if present)
	msp.CRL = make([]*pkix.CertificateList, len(conf.RevocationList))
	for i, crlbytes := range conf.RevocationList {
		crl, err := x509.ParseCRL(crlbytes)
		if err != nil {
			return errors.Wrap(err, "could not parse RevocationList")
		}

		msp.CRL[i] = crl
	}

	return nil
}
func (msp *bccspmsp) setupCAs(conf *msppb.FabricMSPConfig) error {
	if len(conf.RootCerts) == 0 {
		return errors.New("expected at least one CA certificate")
	}
	msp.opts = &x509.VerifyOptions{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool()}
	for _, v := range conf.RootCerts {
		cert, err := msp.getCertFromPem(v)
		if err != nil {
			return err
		}
		msp.opts.Roots.AddCert(cert)
	}
	for _, v := range conf.IntermediateCerts {
		cert, err := msp.getCertFromPem(v)
		if err != nil {
			return err
		}
		msp.opts.Intermediates.AddCert(cert)
	}
	msp.rootCerts = make([]Identity, len(conf.RootCerts))
	for i, trustedCert := range conf.RootCerts {
		id, _, err := msp.getIdentityFromConf(trustedCert)
		if err != nil {
			return err
		}

		msp.rootCerts[i] = id
	}

	// make and fill the set of intermediate certs (if present)
	msp.intermediateCerts = make([]Identity, len(conf.IntermediateCerts))
	for i, trustedCert := range conf.IntermediateCerts {
		id, _, err := msp.getIdentityFromConf(trustedCert)
		if err != nil {
			return err
		}

		msp.intermediateCerts[i] = id
	}
	msp.opts = &x509.VerifyOptions{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool()}
	for _, id := range msp.rootCerts {
		msp.opts.Roots.AddCert(id.(*identity).cert)
	}
	for _, id := range msp.intermediateCerts {
		msp.opts.Intermediates.AddCert(id.(*identity).cert)
	}
	return nil

}
func (msp *bccspmsp) finalizeSetupCAs() error {
	for _, id := range append(append([]Identity{}, msp.rootCerts...), msp.intermediateCerts...) {
		if !id.(*identity).cert.IsCA {
			return errors.Errorf("CA Certificate did not have the CA attribute, (SN: %x)", id.(*identity).cert.SerialNumber)
		}
		if _, err := getSubjectKeyIdentifierFromCert(id.(*identity).cert); err != nil {
			return errors.WithMessagef(err, "CA Certificate problem with Subject Key Identifier extension, (SN: %x)", id.(*identity).cert.SerialNumber)
		}

		if err := msp.validateCAIdentity(id.(*identity)); err != nil {
			return errors.WithMessagef(err, "CA Certificate is not valid, (SN: %s)", id.(*identity).cert.SerialNumber)
		}
	}

	// populate certificationTreeInternalNodesMap to mark the internal nodes of the
	// certification tree
	msp.certificationTreeInternalNodesMap = make(map[string]bool)
	for _, id := range append([]Identity{}, msp.intermediateCerts...) {
		chain, err := msp.getUniqueValidationChain(id.(*identity).cert, msp.getValidityOptsForCert(id.(*identity).cert))
		if err != nil {
			return errors.WithMessagef(err, "failed getting validation chain, (SN: %s)", id.(*identity).cert.SerialNumber)
		}

		// Recall chain[0] is id.(*identity).id so it does not count as a parent
		for i := 1; i < len(chain); i++ {
			msp.certificationTreeInternalNodesMap[string(chain[i].Raw)] = true
		}
	}

	return nil
}

func (msp *bccspmsp) validateCAIdentity(id *identity) error {
	if !id.cert.IsCA {
		return errors.New("Only CA identities can be validated")
	}

	validationChain, err := msp.getUniqueValidationChain(id.cert, msp.getValidityOptsForCert(id.cert))
	if err != nil {
		return errors.WithMessage(err, "could not obtain certification chain")
	}
	if len(validationChain) == 1 {
		// validationChain[0] is the root CA certificate
		return nil
	}

	return msp.validateIdentityAgainstChain(id, validationChain)
}

func (msp *bccspmsp) getSigningIdentityFromConf(sidInfo *msppb.SigningIdentityInfo) (SigningIdentity, error) {
	if sidInfo == nil {
		return nil, errors.New("getIdentityFromBytes error: nil sidInfo")
	}

	// Extract the public part of the identity
	idPub, pubKey, err := msp.getIdentityFromConf(sidInfo.PublicSigner)
	if err != nil {
		return nil, err
	}

	// Find the matching private key in the BCCSP keystore
	privKey, err := msp.bccsp.GetKey(pubKey.SKI())
	// Less Secure: Attempt to import Private Key from KeyInfo, if BCCSP was not able to find the key
	if err != nil {
		if sidInfo.PrivateSigner == nil || sidInfo.PrivateSigner.KeyMaterial == nil {
			return nil, errors.New("KeyMaterial not found in SigningIdentityInfo")
		}

		pemKey, _ := pem.Decode(sidInfo.PrivateSigner.KeyMaterial)
		if pemKey == nil {
			return nil, errors.Errorf("%s: wrong PEM encoding", sidInfo.PrivateSigner.KeyIdentifier)
		}
		privKey, err = msp.bccsp.KeyImport(pemKey.Bytes, &bccsp.ECDSAPrivateKeyImportOpts{Temporary: true})
		if err != nil {
			return nil, errors.WithMessage(err, "getIdentityFromBytes error: Failed to import EC private key")
		}
	}

	// get the peer signer
	peerSigner, err := signer.New(msp.bccsp, privKey)
	if err != nil {
		return nil, errors.WithMessage(err, "getIdentityFromBytes error: Failed initializing bccspCryptoSigner")
	}

	return newSigningIdentity(idPub.(*identity).cert, idPub.(*identity).pk, peerSigner, msp)
}

func (msp *bccspmsp) setupSigningIdentity(conf *msppb.FabricMSPConfig) error {
	if conf.SigningIdentity != nil {
		sid, err := msp.getSigningIdentityFromConf(conf.SigningIdentity)
		if err != nil {
			return err
		}

		expirationTime := sid.ExpiresAt()
		now := time.Now()
		if expirationTime.After(now) {
			//			mspLogger.Debug("Signing identity expires at", expirationTime)
		} else if expirationTime.IsZero() {
			//			mspLogger.Debug("Signing identity has no known expiration time")
		} else {
			return errors.Errorf("signing identity expired %v ago", now.Sub(expirationTime))
		}

		msp.signer = sid
	}

	return nil
}

func (msp *bccspmsp) validateTLSCAIdentity(cert *x509.Certificate, opts *x509.VerifyOptions) error {
	if !cert.IsCA {
		return errors.New("Only CA identities can be validated")
	}

	validationChain, err := msp.getUniqueValidationChain(cert, *opts)
	if err != nil {
		return errors.WithMessage(err, "could not obtain certification chain")
	}
	if len(validationChain) == 1 {
		// validationChain[0] is the root CA certificate
		return nil
	}

	return msp.validateCertAgainstChain(cert, validationChain)
}

func (msp *bccspmsp) setupTLSCAs(conf *msppb.FabricMSPConfig) error {
	opts := &x509.VerifyOptions{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool()}

	// Load TLS root and intermediate CA identities
	msp.tlsRootCerts = make([][]byte, len(conf.TlsRootCerts))
	rootCerts := make([]*x509.Certificate, len(conf.TlsRootCerts))
	for i, trustedCert := range conf.TlsRootCerts {
		cert, err := msp.getCertFromPem(trustedCert)
		if err != nil {
			return err
		}

		rootCerts[i] = cert
		msp.tlsRootCerts[i] = trustedCert
		opts.Roots.AddCert(cert)
	}

	// make and fill the set of intermediate certs (if present)
	msp.tlsIntermediateCerts = make([][]byte, len(conf.TlsIntermediateCerts))
	intermediateCerts := make([]*x509.Certificate, len(conf.TlsIntermediateCerts))
	for i, trustedCert := range conf.TlsIntermediateCerts {
		cert, err := msp.getCertFromPem(trustedCert)
		if err != nil {
			return err
		}

		intermediateCerts[i] = cert
		msp.tlsIntermediateCerts[i] = trustedCert
		opts.Intermediates.AddCert(cert)
	}

	// ensure that our CAs are properly formed and that they are valid
	for _, cert := range append(append([]*x509.Certificate{}, rootCerts...), intermediateCerts...) {
		if cert == nil {
			continue
		}

		if !cert.IsCA {
			return errors.Errorf("CA Certificate did not have the CA attribute, (SN: %x)", cert.SerialNumber)
		}
		if _, err := getSubjectKeyIdentifierFromCert(cert); err != nil {
			return errors.WithMessagef(err, "CA Certificate problem with Subject Key Identifier extension, (SN: %x)", cert.SerialNumber)
		}

		if err := msp.validateTLSCAIdentity(cert, opts); err != nil {
			return errors.WithMessagef(err, "CA Certificate is not valid, (SN: %s)", cert.SerialNumber)
		}
	}

	return nil
}

func (msp *bccspmsp) getCertifiersIdentifier(certRaw []byte) ([]byte, error) {
	// 1. check that certificate is registered in msp.rootCerts or msp.intermediateCerts
	cert, err := msp.getCertFromPem(certRaw)
	if err != nil {
		return nil, fmt.Errorf("Failed getting certificate for [%v]: [%s]", certRaw, err)
	}

	// 2. Sanitize it to ensure like for like comparison
	//cert, err = msp.sanitizeCert(cert)
	//if err != nil {
	//	return nil, fmt.Errorf("sanitizeCert failed %s", err)
	//}

	found := false
	root := false
	// Search among root certificates
	for _, v := range msp.rootCerts {
		if v.(*identity).cert.Equal(cert) {
			found = true
			root = true
			break
		}
	}
	if !found {
		// Search among root intermediate certificates
		for _, v := range msp.intermediateCerts {
			if v.(*identity).cert.Equal(cert) {
				found = true
				break
			}
		}
	}
	if !found {
		// Certificate not valid, reject configuration
		return nil, fmt.Errorf("Failed adding OU. Certificate [%v] not in root or intermediate certs.", cert)
	}

	// 3. get the certification path for it
	var certifiersIdentifier []byte
	var chain []*x509.Certificate
	if root {
		chain = []*x509.Certificate{cert}
	} else {
		chain, err = msp.getValidationChain(cert, true)
		if err != nil {
			return nil, fmt.Errorf("Failed computing validation chain for [%v]. [%s]", cert, err)
		}
	}

	// 4. compute the hash of the certification path
	certifiersIdentifier, err = msp.getCertificationChainIdentifierFromChain(chain)
	if err != nil {
		return nil, fmt.Errorf("Failed computing Certifiers Identifier for [%v]. [%s]", certRaw, err)
	}

	return certifiersIdentifier, nil
}

func (msp *bccspmsp) setupOUs(conf *msppb.FabricMSPConfig) error {
	msp.ouIdentifiers = make(map[string][][]byte)
	for _, ou := range conf.OrganizationalUnitIdentifiers {

		certifiersIdentifier, err := msp.getCertifiersIdentifier(ou.Certificate)
		if err != nil {
			return errors.WithMessagef(err, "failed getting certificate for [%v]", ou)
		}

		// Check for duplicates
		found := false
		for _, id := range msp.ouIdentifiers[ou.OrganizationalUnitIdentifier] {
			if bytes.Equal(id, certifiersIdentifier) {
				found = true
				break
			}
		}

		if !found {
			// No duplicates found, add it
			msp.ouIdentifiers[ou.OrganizationalUnitIdentifier] = append(
				msp.ouIdentifiers[ou.OrganizationalUnitIdentifier],
				certifiersIdentifier,
			)
		}
	}

	return nil
}

func (msp *bccspmsp) setupNodeOUsV142(config *msppb.FabricMSPConfig) error {
	if config.FabricNodeOus == nil {
		msp.ouEnforcement = false
		return nil
	}

	msp.ouEnforcement = config.FabricNodeOus.Enable

	counter := 0
	// ClientOU
	if config.FabricNodeOus.ClientOuIdentifier != nil {
		msp.clientOU = &OUIdentifier{OrganizationalUnitIdentifier: config.FabricNodeOus.ClientOuIdentifier.OrganizationalUnitIdentifier}
		if len(config.FabricNodeOus.ClientOuIdentifier.Certificate) != 0 {
			certifiersIdentifier, err := msp.getCertifiersIdentifier(config.FabricNodeOus.ClientOuIdentifier.Certificate)
			if err != nil {
				return err
			}
			msp.clientOU.CertifiersIdentifier = certifiersIdentifier
		}
		counter++
	} else {
		msp.clientOU = nil
	}

	// PeerOU
	if config.FabricNodeOus.PeerOuIdentifier != nil {
		msp.peerOU = &OUIdentifier{OrganizationalUnitIdentifier: config.FabricNodeOus.PeerOuIdentifier.OrganizationalUnitIdentifier}
		if len(config.FabricNodeOus.PeerOuIdentifier.Certificate) != 0 {
			certifiersIdentifier, err := msp.getCertifiersIdentifier(config.FabricNodeOus.PeerOuIdentifier.Certificate)
			if err != nil {
				return err
			}
			msp.peerOU.CertifiersIdentifier = certifiersIdentifier
		}
		counter++
	} else {
		msp.peerOU = nil
	}

	// AdminOU
	if config.FabricNodeOus.AdminOuIdentifier != nil {
		msp.adminOU = &OUIdentifier{OrganizationalUnitIdentifier: config.FabricNodeOus.AdminOuIdentifier.OrganizationalUnitIdentifier}
		if len(config.FabricNodeOus.AdminOuIdentifier.Certificate) != 0 {
			certifiersIdentifier, err := msp.getCertifiersIdentifier(config.FabricNodeOus.AdminOuIdentifier.Certificate)
			if err != nil {
				return err
			}
			msp.adminOU.CertifiersIdentifier = certifiersIdentifier
		}
		counter++
	} else {
		msp.adminOU = nil
	}

	// OrdererOU
	if config.FabricNodeOus.OrdererOuIdentifier != nil {
		msp.ordererOU = &OUIdentifier{OrganizationalUnitIdentifier: config.FabricNodeOus.OrdererOuIdentifier.OrganizationalUnitIdentifier}
		if len(config.FabricNodeOus.OrdererOuIdentifier.Certificate) != 0 {
			certifiersIdentifier, err := msp.getCertifiersIdentifier(config.FabricNodeOus.OrdererOuIdentifier.Certificate)
			if err != nil {
				return err
			}
			msp.ordererOU.CertifiersIdentifier = certifiersIdentifier
		}
		counter++
	} else {
		msp.ordererOU = nil
	}

	if counter == 0 {
		// Disable NodeOU
		msp.ouEnforcement = false
	}

	return nil
}

func (msp *bccspmsp) setupAdminsPreV142(conf *msppb.FabricMSPConfig) error {
	// make and fill the set of admin certs (if present)
	msp.admins = make([]Identity, len(conf.Admins))
	for i, admCert := range conf.Admins {
		id, _, err := msp.getIdentityFromConf(admCert)
		if err != nil {
			return err
		}

		msp.admins[i] = id
	}

	return nil
}
