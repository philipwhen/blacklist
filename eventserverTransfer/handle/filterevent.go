package handle

import (
	"encoding/json"
	//"fmt"
	//"time"

	"github.com/peersafe/poc_blacklist/apiserver/define"

	protos_peer "github.com/hyperledger/fabric/protos/peer"
	"github.com/op/go-logging"
)

var (
	logger = logging.MustGetLogger("filter-event")
)

func FilterEvent(event *protos_peer.ChaincodeEvent) (interface{}, bool) {
	logger.Info("enter filterevent function......")
	responseData := define.InvokeResponse{}
	blkList := define.BlacklistKeyData{}
	responseData.Payload = &blkList

	logger.Infof("unmarshal payload is %s.", string(event.Payload))
	err := json.Unmarshal(event.Payload, &responseData)
	if err != nil {
		logger.Errorf("unmarshal payload failed: %s.", err)
		return nil, false
	} else {
		for _, blkListData := range blkList.BlkLists {
			logger.Infof("liststatus is %d", blkListData.CommData.ListStatus)
		}

		//ListStatus is uint64 type which can be set to be the sending time.
		//Please ignore the meaning of this field itself.
		/*
			currentTime := time.Now()
			timeDiff := currentTime.UnixNano()/1000000 - int64(blkList.CommData.ListStatus)
			fmt.Println(timeDiff)
		*/
	}

	return blkList, true
}
