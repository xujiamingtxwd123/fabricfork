package common

import (
	"errors"
	"github.com/spf13/viper"
	"os"
	"strings"

	"fabricfork/msp"
	"github.com/hyperledger/fabric/bccsp/factory"
)

func LoadConfig() error{
	viper.SetEnvPrefix("core")
	viper.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)

	altPath := os.Getenv("FABRIC_CFG_PATH")
	viper.AddConfigPath(altPath)
	viper.SetConfigName("core")
	return viper.ReadInConfig()
}

func InitCmd() error {
	var mspMgrConfigDir = viper.GetString("peer.mspConfigPath")
	var mspID = viper.GetString("peer.localMspId")
	var mspType = viper.GetString("peer.localMspType")
	if mspType == "" {
		mspType = msp.ProviderTypeToString(msp.FABRIC)
	}

	return InitCrypto(mspMgrConfigDir, mspID, mspType)
}

func InitCrypto(mspMgrConfigDir, localMSPID, localMSPType string) error {
	if localMSPID == "" {
		return errors.New("mspid is null")
	}
	bccspConfig := factory.GetDefaultOpts()
	//将配置文件、证书文件都读取到conf中，不包含keystore，keystore 存储在bccspConfig
	conf, err := msp.GetLocalMspConfig(mspMgrConfigDir, localMSPID, bccspConfig)
	if err != nil {
		return err
	}
	err = msp.GetLocalMSP(factory.GetDefault()).Setup(conf)
	if err != nil {
		return err
	}

	return nil
}
