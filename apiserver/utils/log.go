package utils

import (
    "os"
    "time"
    "fmt"
    "github.com/op/go-logging"
)

var (
    LOGLEVEL int = 5
    Log = logging.MustGetLogger("apiserver")
    format = logging.MustStringFormatter(`%{shortfile} %{time:15:04:05.000} %{shortfunc} > %{level:.4s} %{id:03x} %{message}`)
)

func init() {
	currectTime := time.Now()
	fileName := fmt.Sprintf("apiserver-%d-%d-%d-%d-%d-log", currectTime.Year(), currectTime.Month(), currectTime.Day(),
		                                                    currectTime.Hour(), currectTime.Minute())
	logFile, err := os.Create(fileName)
	if err != nil{
        fmt.Println(err)
        os.Exit(1)
    }
    backend1 := logging.NewLogBackend(logFile, "", 0)
    backendFormatter := logging.NewBackendFormatter(backend1, format)
    if LOGLEVEL > 5 || LOGLEVEL < 0 { 
        LOGLEVEL = 5
    }
    logging.SetBackend(backendFormatter).SetLevel(logging.Level(LOGLEVEL), "")

    Log.Critical("-------------------------------------------------------------------")
    Log.Critical("                        WELCOME!                                   ")
    Log.Critical("    ",                         currectTime                          )
    Log.Critical("-------------------------------------------------------------------")
    Log.Critical("logger lever is", LOGLEVEL)
}