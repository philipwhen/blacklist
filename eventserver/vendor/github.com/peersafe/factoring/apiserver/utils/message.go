package utils

import (
	"encoding/json"
	"fmt"

	"github.com/peersafe/factoring/apiserver/define"
)

var broadcastTag = "ALL"

// FormatRequestMessage format requset to message json
func FormatRequestMessage(request define.Factor) ([]byte, error) {
	//CryptoAlgorithm is used by hoperun, we don't need to care about it. By wuxu, 20170901.
	//request.CryptoAlgorithm = "aes"
	var invokeRequest define.InvokeRequest
	peerasfeData := define.PeersafeData{}
	peerasfeData.Keys = make(map[string][]byte)
	key := GenerateKey(32)
	if request.CryptoFlag == 1 {
		cryptoData, err := AesEncrypt([]byte(request.TxData), key)
		if err != nil {
			return nil, fmt.Errorf("AesEncrypt data error : %s", err.Error())
		}
		request.TxData = string(cryptoData)
		for _, receiver := range request.Receiver {
			path := define.CRYPTO_PATH + receiver + "/" + "enrollment.cert"
			cert, err := ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("ReadFile %s cert error : %s", receiver, err.Error())
			}

			cryptoKey, err := EciesEncrypt(key, cert)
			if err != nil {
				return nil, fmt.Errorf("EciesEncrypt %s reandom key error : %s", receiver, err.Error())
			}

			peerasfeData.Keys[receiver] = cryptoKey
		}
	}

	message := &define.Message{}
	message.CreateBy = request.CreateBy
	message.CreateTime = request.CreateTime
	message.Sender = request.Sender
	message.Receiver = request.Receiver
	message.TxData = request.TxData
	message.LastUpdateTime = request.LastUpdateTime
	message.LastUpdateBy = request.LastUpdateBy
	message.CryptoFlag = request.CryptoFlag
	message.CryptoAlgorithm = request.CryptoAlgorithm
	message.DocType = request.DocType
	message.FabricTxId = request.FabricTxId
	message.BusinessNo = request.BusinessNo
	message.Expand1 = request.Expand1
	message.Expand2 = request.Expand2
	message.DataVersion = request.DataVersion
	message.PeersafeData = peerasfeData

	b, _ := json.Marshal(message)
	invokeRequest.Value = string(b)
	invokeRequest.Key = request.FabricTxId

	return json.Marshal(invokeRequest)
}

// FormatResponseMessage format response to message json
func FormatResponseMessage(userId string, request *[]define.Factor, messages *[]define.Message) error {
	for i := 0; i < len(*messages); i++ {
		item := (*messages)[i]
		var isReceiver = false
		var isBroadcast = false
		for _, v := range item.Receiver {
			if broadcastTag  == v {
				isReceiver = true
				isBroadcast = true
				break
			}
			if userId == v {
				isReceiver = true
				break
			}
		}
		if !isReceiver {
			fmt.Printf("The node is not the message's(%s) receiver\n", item.FabricTxId)
			continue
		}
		if isBroadcast {
			fmt.Printf("The message is a broadcast message\n")
		}

		if item.CryptoFlag == 1 {
			if isBroadcast {
				return fmt.Errorf("The message is a broadcast message, but it is crypto message!")
			}
			cryptoKey, ok := item.PeersafeData.Keys[userId]
			if !ok {
				return fmt.Errorf("The message is for %s, but it does not has the user's cryptoKey", userId)
			}
			path := define.CRYPTO_PATH + userId + "/" + "enrollment.key"
			privateKey, err := ReadFile(path)
			if err != nil {
				return fmt.Errorf("ReadFile %s key error : %s", userId, err.Error())
			}

			key, err := EciesDecrypt(cryptoKey, privateKey)
			if err != nil {
				return fmt.Errorf("EciesDecrypt %s random key error : %s", userId, err.Error())
			}

			data, err := AesDecrypt([]byte(item.TxData), key)
			if err != nil {
				return fmt.Errorf("AesDecrypt %s data error : %s", userId, err.Error())
			}
			item.TxData = string(data)
		}

		factor := define.Factor{
			CreateBy:        item.CreateBy,
			CreateTime:      item.CreateTime,
			Sender:          item.Sender,
			Receiver:        item.Receiver,
			TxData:          item.TxData,
			LastUpdateTime:  item.LastUpdateTime,
			LastUpdateBy:    item.LastUpdateBy,
			CryptoFlag:      item.CryptoFlag,
			CryptoAlgorithm: item.CryptoAlgorithm,
			DocType:         item.DocType,
			FabricTxId:      item.FabricTxId,
			BusinessNo:      item.BusinessNo,
			Expand1:         item.Expand1,
			Expand2:         item.Expand2,
			DataVersion:     item.DataVersion,
		}
		*request = append(*request, factor)
	}
	if 0 == len(*request) {
		return fmt.Errorf("The node is not the messages' receiver")
	}
	return nil
}
