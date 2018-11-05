package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"syscall"

	"github.com/peersafe/poc_blacklist/apiserver/handler"
	"github.com/peersafe/poc_blacklist/apiserver/router"
	"github.com/peersafe/poc_blacklist/apiserver/sdk"
	"github.com/peersafe/poc_blacklist/apiserver/utils"

	"github.com/DeanThompson/ginpprof"
	"github.com/fvbock/endless"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

var (
	VERSION = "1.0.0"

	configPath = flag.String("configPath", "", "config file path")
	configName = flag.String("configName", "", "config file name")
	isVersion  = flag.Bool("version", false, "show the version info")
)

func main() {
	// parse init param
	utils.Log.Debug("Usage : ./apiserver -version -configPath= -configName=")
	flag.Parse()

	if *isVersion {
		fmt.Println("------------------------------------------------------")
		fmt.Println("    The version of the apiserver is:", VERSION)
		fmt.Println("------------------------------------------------------")
		os.Exit(0)
	}

	if *configPath == "" || *configName == "" {
		*configPath = "./"
		*configName = "client_sdk"
		utils.Log.Debug("becase configPath or configName nil  so  auto set")
		utils.Log.Debug("auto set  configPath = \"./\" , configName = \"client_sdk\"")
	}

	err := sdk.InitSDK(*configPath, *configName)
	if err != nil {
		utils.Log.Errorf("init sdk error : %s\n", err.Error())
		panic(err)
	}

	// 设置使用系统最大CPU
	runtime.GOMAXPROCS(runtime.NumCPU())

	// 运行模式
	gin.SetMode(gin.ReleaseMode) //ReleaseMode DebugMode

	// 构造路由器
	r := router.GetRouter()

	// 调试用,可以看到堆栈状态和所有goroutine状态
	ginpprof.Wrapper(r)

	//Get the listen port for apiserver
	listenPort := viper.GetInt("apiserver.listenport")
	//listenPort = 8888
	utils.Log.Debug("The listen port is", listenPort)
	listenPortString := fmt.Sprintf(":%d", listenPort)

	//TODO: use .so to encrypt special data.
	utils.PushUrl = viper.GetString("chainsql.url")
	utils.EventAddress = viper.GetString("peer.listenAddress")
	utils.ChainID = viper.GetString("chaincode.id.chainID")
	/*
		pubKey := viper.GetString("chainsql.defaultkey")
		if pubKey != "" {
			utils.DefaultPubKey = pubKey
		}
	*/

	if !handler.SetOrderAddrToProbe(viper.GetString("apiserver.probe_order")) {
		panic("can not get the order address to be probed.")
	}

	// 运行服务
	server := endless.NewServer(listenPortString, r)
	server.BeforeBegin = func(add string) {
		pid := syscall.Getpid()
		utils.Log.Critical("Actual pid is", pid)
		// 保存pid文件
		pidFile := "apiserver.pid"
		if checkFileIsExist(pidFile) {
			os.Remove(pidFile)
		} else {
			if err := ioutil.WriteFile(pidFile, []byte(fmt.Sprintf("%d", pid)), 0666); err != nil {
				utils.Log.Fatalf("Api server write pid file failed! err:%v\n", err)
			}
		}
	}
	err = server.ListenAndServe()
	if err != nil {
		if strings.Contains(err.Error(), "use of closed network connection") {
			utils.Log.Errorf("%v\n", err)
		} else {
			utils.Log.Errorf("Api server start failed! err:%v\n", err)
			panic(err)
		}
	}
}

func checkFileIsExist(filename string) bool {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return false
	}
	return true
}
