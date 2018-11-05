package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/hyperledger/fabric-sdk-go-peersafe/pkg/common"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/peersafe/poc_blacklist/eventserverTransfer/handle"
	le "github.com/peersafe/poc_blacklist/eventserverTransfer/listenevent"

	cp "github.com/hyperledger/fabric-sdk-go-peersafe/pkg/common/peer"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
)

var (
	logOutput  = os.Stderr
	configPath = flag.String("configPath", "./", "config path")
	configName = flag.String("configName", "client_sdk", "config file name")
)

const CHANNELBUFFER = 1000

func main() {
	flag.Parse()
	err := common.InitSDK(*configPath, *configName)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	runtime.GOMAXPROCS(viper.GetInt("peer.gomaxprocs"))

	//setup system-wide logging backend based on settings from core.yaml
	flogging.InitBackend(flogging.SetFormat(viper.GetString("logging.format")), logOutput)
	logging.SetLevel(logging.DEBUG, "client_sdk")

	logger := logging.MustGetLogger("main")

	eventAddress := viper.GetString("peer.listenAddress")
	chainID := viper.GetString("chaincode.id.chainID")

	handle.ChainsqlUrl = viper.GetString("chainsql.payurl")
	handle.ChainsqlRateLimit = viper.GetFloat64("chainsql.ratelimit")
	handle.ChainsqlTimeout = viper.GetDuration("chainsql.timeout")
	handle.Sqlite3DbPath = viper.GetString("sqlite3.dbpath")

	peerClients := cp.GetPeerClients("", true)
	if !handle.GetBlockHeight(peerClients, chainID) {
		logger.Panic("Get block height failed!")
	}

	listenToHandle := make(chan handle.BlockInfoAll, CHANNELBUFFER)

	//check and recover the message
	go handle.CheckAndRecoverEvent(peerClients, chainID, handle.FilterEvent, listenToHandle)

	//listen the block event and parse the message
	le.ListenEvent(eventAddress, chainID, handle.FilterEvent, listenToHandle)
}
