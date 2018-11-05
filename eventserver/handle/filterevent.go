package handle

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/peersafe/poc_blacklist/apiserver/define"

	protos_peer "github.com/hyperledger/fabric/protos/peer"
	"github.com/op/go-logging"
)

var (
	logger = logging.MustGetLogger("filter-event")
)

func FilterEvent(event *protos_peer.ChaincodeEvent) (interface{}, bool) {
	//	logger.Info("enter filterevent function......")
	responseData := define.InvokeResponse{}
	blkList := define.BlacklistKeyData{}
	responseData.Payload = &blkList

	//	logger.Infof("unmarshal payload is %s.", string(event.Payload))
	_ = json.Unmarshal(event.Payload, &responseData)
	if blkList.DataType != 1 {
		responseData1 := define.InvokeResponse{}
		payResCC := define.PaymentResponseCC{}
		responseData1.Payload = &payResCC
		err1 := json.Unmarshal(event.Payload, &responseData1)
		if err1 != nil {
			//			logger.Errorf("unmarshal payload failed: %s.", err)
			return nil, false
		} else {
			if payResCC.StatusMsg == "payment success" {
				//				logger.Infof("it is a payment successful reponse")
				return payResCC, true
			} else {
				return nil, false
			}

		}

	} else {
		//		for _, blkListData := range blkList.BlkLists {
		//			logger.Infof("liststatus is %d", blkListData.CommData.ListStatus)
		//		}

		//ListStatus is uint64 type which can be set to be the sending time.
		//Please ignore the meaning of this field itself.
		for _, blkListData := range blkList.BlkLists {
			currentTime := time.Now()

			timeDiff := currentTime.UnixNano()/1000000 - int64(blkListData.CommData.ListStatus)
			fmt.Println(timeDiff)
			break
		}

	}

	return blkList, true
}
