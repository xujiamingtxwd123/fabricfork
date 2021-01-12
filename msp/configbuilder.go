package msp

import (
	"encoding/pem"
	"fmt"
	"github.com/gogo/protobuf/proto"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path/filepath"

	msppb "github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
)

const (
	cacerts              = "cacerts"
	admincerts           = "admincerts"
	signcerts            = "signcerts"
	keystore             = "keystore"
	intermediatecerts    = "intermediatecerts"
	crlsfolder           = "crls"
	configfilename       = "config.yaml"
	tlscacerts           = "tlscacerts"
	tlsintermediatecerts = "tlsintermediatecerts"
)

type OrganizationalUnitIdentifiersConfiguration struct {
	// Certificate is the path to a root or intermediate certificate
	Certificate string `yaml:"Certificate,omitempty"`
	// OrganizationalUnitIdentifier is the name of the OU
	OrganizationalUnitIdentifier string `yaml:"OrganizationalUnitIdentifier,omitempty"`
}

// NodeOUs contains information on how to tell apart clients, peers and orderers
// based on OUs. If the check is enforced, by setting Enabled to true,
// the MSP will consider an identity valid if it is an identity of a client, a peer or
// an orderer. An identity should have only one of these special OUs.
type NodeOUs struct {
	// Enable activates the OU enforcement
	Enable bool `yaml:"Enable,omitempty"`
	// ClientOUIdentifier specifies how to recognize clients by OU
	ClientOUIdentifier *OrganizationalUnitIdentifiersConfiguration `yaml:"ClientOUIdentifier,omitempty"`
	// PeerOUIdentifier specifies how to recognize peers by OU
	PeerOUIdentifier *OrganizationalUnitIdentifiersConfiguration `yaml:"PeerOUIdentifier,omitempty"`
	// AdminOUIdentifier specifies how to recognize admins by OU
	AdminOUIdentifier *OrganizationalUnitIdentifiersConfiguration `yaml:"AdminOUIdentifier,omitempty"`
	// OrdererOUIdentifier specifies how to recognize admins by OU
	OrdererOUIdentifier *OrganizationalUnitIdentifiersConfiguration `yaml:"OrdererOUIdentifier,omitempty"`
}

// Configuration represents the accessory configuration an MSP can be equipped with.
// By default, this configuration is stored in a yaml file
type Configuration struct {
	// OrganizationalUnitIdentifiers is a list of OUs. If this is set, the MSP
	// will consider an identity valid only it contains at least one of these OUs
	OrganizationalUnitIdentifiers []*OrganizationalUnitIdentifiersConfiguration `yaml:"OrganizationalUnitIdentifiers,omitempty"`
	// NodeOUs enables the MSP to tell apart clients, peers and orderers based
	// on the identity's OU.
	NodeOUs *NodeOUs `yaml:"NodeOUs,omitempty"`
}

func GetLocalMspConfig(dir string, localMspId string, bccspConfig *factory.FactoryOpts) (*msppb.MSPConfig, error) {
	signcertDir := filepath.Join(dir, signcerts)
	keystoreDir := filepath.Join(dir, keystore)
	cacertDir := filepath.Join(dir, cacerts)
	admincertDir := filepath.Join(dir, admincerts)
	intermediatecertsDir := filepath.Join(dir, intermediatecerts)
	crlsDir := filepath.Join(dir, crlsfolder)
	configFile := filepath.Join(dir, configfilename)
	tlscacertDir := filepath.Join(dir, tlscacerts)
	tlsintermediatecertsDir := filepath.Join(dir, tlsintermediatecerts)

	rootCert, err := getPemFromDir(cacertDir)
	if err != nil {
		return nil, err
	}

	if len(rootCert) == 0 {
		return nil, errors.New("root cert is null")
	}

	signCert, err := getPemFromDir(signcertDir)
	if err != nil {
		return nil, err
	}
	if len(signCert) == 0 {
		return nil, errors.Errorf("sign cert is null")
	}
	adminCert, err := getPemFromDir(admincertDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	intermediateCert, err := getPemFromDir(intermediatecertsDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	var ouis []*msppb.FabricOUIdentifier
	var nodeOUs *msppb.FabricNodeOUs
	_, err = os.Stat(configFile)
	if err == nil {
		raw, err := ioutil.ReadFile(configFile)
		if err != nil {
			return nil, errors.Wrapf(err, "failed loading configuration file at [%s]", configFile)
		}
		configuration := Configuration{}
		err = yaml.Unmarshal(raw, &configuration)
		if err != nil {
			return nil, errors.Wrapf(err, "failed unmarshalling configuration file at [%s]", configFile)
		}
		for _, ouID := range configuration.OrganizationalUnitIdentifiers {
			f := filepath.Join(dir, ouID.Certificate)
			content, err := ioutil.ReadFile(f)
			if err != nil {
				return nil, errors.Wrapf(err, "failed read ouID %s", ouID)
			}
			oui := &msppb.FabricOUIdentifier{
				Certificate:                  content,
				OrganizationalUnitIdentifier: ouID.OrganizationalUnitIdentifier,
			}
			ouis = append(ouis, oui)
		}

		if configuration.NodeOUs != nil && configuration.NodeOUs.Enable {
			nodeOUs = &msppb.FabricNodeOUs{
				Enable: true,
			}
			if configuration.NodeOUs.ClientOUIdentifier != nil && len(configuration.NodeOUs.ClientOUIdentifier.OrganizationalUnitIdentifier) != 0 {
				nodeOUs.ClientOuIdentifier = &msppb.FabricOUIdentifier{OrganizationalUnitIdentifier: configuration.NodeOUs.ClientOUIdentifier.OrganizationalUnitIdentifier}
			}
			if configuration.NodeOUs.PeerOUIdentifier != nil && len(configuration.NodeOUs.PeerOUIdentifier.OrganizationalUnitIdentifier) != 0 {
				nodeOUs.PeerOuIdentifier = &msppb.FabricOUIdentifier{OrganizationalUnitIdentifier: configuration.NodeOUs.PeerOUIdentifier.OrganizationalUnitIdentifier}
			}
			if configuration.NodeOUs.AdminOUIdentifier != nil && len(configuration.NodeOUs.AdminOUIdentifier.OrganizationalUnitIdentifier) != 0 {
				nodeOUs.AdminOuIdentifier = &msppb.FabricOUIdentifier{OrganizationalUnitIdentifier: configuration.NodeOUs.AdminOUIdentifier.OrganizationalUnitIdentifier}
			}
			if configuration.NodeOUs.OrdererOUIdentifier != nil && len(configuration.NodeOUs.OrdererOUIdentifier.OrganizationalUnitIdentifier) != 0 {
				nodeOUs.OrdererOuIdentifier = &msppb.FabricOUIdentifier{OrganizationalUnitIdentifier: configuration.NodeOUs.OrdererOUIdentifier.OrganizationalUnitIdentifier}
			}

			// Read certificates, if defined

			// ClientOU
			if nodeOUs.ClientOuIdentifier != nil {
				nodeOUs.ClientOuIdentifier.Certificate = loadCertificateAt(dir, configuration.NodeOUs.ClientOUIdentifier.Certificate, "ClientOU")
			}
			// PeerOU
			if nodeOUs.PeerOuIdentifier != nil {
				nodeOUs.PeerOuIdentifier.Certificate = loadCertificateAt(dir, configuration.NodeOUs.PeerOUIdentifier.Certificate, "PeerOU")
			}
			// AdminOU
			if nodeOUs.AdminOuIdentifier != nil {
				nodeOUs.AdminOuIdentifier.Certificate = loadCertificateAt(dir, configuration.NodeOUs.AdminOUIdentifier.Certificate, "AdminOU")
			}
			// OrdererOU
			if nodeOUs.OrdererOuIdentifier != nil {
				nodeOUs.OrdererOuIdentifier.Certificate = loadCertificateAt(dir, configuration.NodeOUs.OrdererOUIdentifier.Certificate, "OrdererOU")
			}
		}
	}

	cryptoConfig := &msppb.FabricCryptoConfig{
		SignatureHashFamily:            bccsp.SHA2,
		IdentityIdentifierHashFunction: bccsp.SHA256,
	}

	tlscaCert, err := getPemFromDir(tlscacertDir)
	if err != nil {
		return nil, err
	}
	tlsIntermediateCerts, err := getPemFromDir(tlsintermediatecertsDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	crlsCert, err := getPemFromDir(crlsDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	bccspConfig.SwOpts.Ephemeral = false
	bccspConfig.SwOpts.FileKeystore = &factory.FileKeystoreOpts{KeyStorePath: keystoreDir}

	err = factory.InitFactories(bccspConfig)
	if err != nil {
		return nil, err
	}

	mspid := &msppb.SigningIdentityInfo{PublicSigner: signCert[0]}
	fmspconf := &msppb.FabricMSPConfig{
		Name:                          localMspId,
		RootCerts:                     rootCert,
		SigningIdentity:               mspid,
		Admins:                        adminCert,
		IntermediateCerts:             intermediateCert,
		OrganizationalUnitIdentifiers: ouis,
		FabricNodeOus:                 nodeOUs, //TODO xjm  如何使用的
		CryptoConfig:                  cryptoConfig,
		TlsRootCerts:                  tlscaCert,
		TlsIntermediateCerts:          tlsIntermediateCerts,
		RevocationList:                crlsCert,
	}
	mspMarshal, _ := proto.Marshal(fmspconf)
	mspconf := &msppb.MSPConfig{Config: mspMarshal, Type: int32(FABRIC)}
	return mspconf, nil
}

func getPemFromDir(dir string) ([][]byte, error) {
	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return nil, err
	}
	content := make([][]byte, 0)
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, errors.Wrapf(err, "could not read directory %s", dir)
	}
	for _, f := range files {
		fullName := filepath.Join(dir, f.Name())

		f, err := os.Stat(fullName)
		if err != nil {
			fmt.Printf("Failed to stat %s: %s\n", fullName, err)
			continue
		}
		if f.IsDir() {
			continue
		}

		item, err := readPemFile(fullName)
		if err != nil {
			fmt.Printf("Failed reading file %s: %s\n", fullName, err)
			continue
		}

		content = append(content, item)
	}

	return content, nil

}
func readPemFile(file string) ([]byte, error) {
	fileCont, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, errors.Wrapf(err, "could not read file %s", file)
	}
	b, _ := pem.Decode(fileCont)
	if b == nil { // TODO: also check that the type is what we expect (cert vs key..)
		return nil, errors.Errorf("no pem content for file %s", file)
	}

	return fileCont, nil
}

func loadCertificateAt(dir, certificatePath string, ouType string) []byte {
	if certificatePath == "" {
		return nil
	}

	f := filepath.Join(dir, certificatePath)
	raw, err := ioutil.ReadFile(f)
	if err != nil {
		return nil
	}

	return raw
}
