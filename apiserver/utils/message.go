package utils

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	listener "github.com/hyperledger/fabric-sdk-go-peersafe/pkg/block-listener"
	"github.com/hyperledger/fabric/core/ledger/util"
	pc "github.com/hyperledger/fabric/protos/common"
	protos_peer "github.com/hyperledger/fabric/protos/peer"
	putils "github.com/hyperledger/fabric/protos/utils"
	"github.com/peersafe/poc_blacklist/apiserver/define"
)

var PushUrl string
var EventAddress string
var ChainID string

//var DefaultPubKey string = "cB4Yp2i2Qv1t8o3YdXzySgJAgD41sUGE6aQWi15CRNkxA3jKj6mU"
func GetReceivedMessage(ccrequestparam define.PaymentParamCC) interface{} {
	notfy := listener.GetListenChannel(EventAddress, ChainID)
	if notfy == nil {
		return fmt.Errorf("The Listen event notify is empty!")
	}
	for {
		select {
		case b := <-notfy:
			var block = b.Block
			txsFltr := util.TxValidationFlags(block.Metadata.Metadata[pc.BlockMetadataIndex_TRANSACTIONS_FILTER])
			//var blockNum = block.Header.Number
			for txIndex, r := range block.Data.Data {
				msg, err := func() (interface{}, error) {
					tx, err := listener.GetTxPayload(r)
					if tx != nil || err != nil {
						chdr, err := putils.UnmarshalChannelHeader(tx.Header.ChannelHeader)
						if err != nil {
							return nil, fmt.Errorf("Error extracting channel header")
						}
						var isInvalidTx = txsFltr.IsInvalid(txIndex)
						event, err := listener.GetChainCodeEvents(tx)
						if err != nil {
							if isInvalidTx {
								return nil, fmt.Errorf("Received invalidTx from channel '%s': %s", chdr.ChannelId, err.Error())
							} else {
								return nil, fmt.Errorf("Received failed from channel '%s':%s", chdr.ChannelId, err.Error())
							}
						}
						//match the corresponding chainID
						if len(ChainID) != 0 && chdr.ChannelId != ChainID {
							return nil, fmt.Errorf("Wrong ChannelID %s", chdr.ChannelId)
						}
						//filter msg from chiancode event
						var msg, ok = FilterEvent(event, ccrequestparam)
						if ok {
							return msg, nil
						} else {
							return nil, fmt.Errorf("Not right tx")
						}
					}
					return nil, fmt.Errorf("Get tx payload is failed:%v, err:%v", tx, err)
				}()
				if err == nil {
					return msg
				}
			}
		}
	}
}

func FilterEvent(event *protos_peer.ChaincodeEvent, ccrequestparam define.PaymentParamCC) (interface{}, bool) {
	//logger.Info("enter filterevent function......")
	responseData := define.InvokeResponse{}
	payResCC := define.PaymentResponseCC{}
	responseData.Payload = &payResCC

	//logger.Infof("unmarshal payload is %s.", string(event.Payload))
	err := json.Unmarshal(event.Payload, &responseData)
	Log.Debug("unmarshal payload is %s.", string(event.Payload))
	if err != nil {
		//logger.Errorf("unmarshal payload failed: %s.", err)
		return nil, false
	} else {
		if payResCC.StatusMsg != "send success" {
			return nil, false
		}
		if payResCC.SourceAddress != ccrequestparam.SourceAddress || payResCC.PubKey != ccrequestparam.PubKey || payResCC.DestinationAddress != ccrequestparam.DestinationAddress || payResCC.EncryptData != ccrequestparam.EncryptData || payResCC.EncryptKey == ccrequestparam.EncryptKey {
			return nil, false
		}
	}

	return payResCC, true
}
func GetTranDateTime() define.CreatTime {
	var t define.CreatTime
	currentTime := time.Now()

	t.Year = fmt.Sprintf("%d", currentTime.Year())
	t.Month = fmt.Sprintf("%d", currentTime.Month())
	t.Day = fmt.Sprintf("%d", currentTime.Day())
	t.Hour = fmt.Sprintf("%d", currentTime.Hour())
	t.Minute = fmt.Sprintf("%d", currentTime.Minute())
	t.Second = fmt.Sprintf("%d", currentTime.Second())

	return t
}

func SendChainSqlMessage(data []byte) ([]byte, error) {
	PostFunc := func(data []byte) ([]byte, error) {
		req, err := http.NewRequest("POST", PushUrl, bytes.NewBuffer(data))
		if err != nil {
			Log.Errorf("New post request error , %s", err.Error())
			return []byte("empty"), err
		}
		//req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			Log.Errorf("client do error , %s", err.Error())
			return []byte("empty"), err
		}
		defer resp.Body.Close()
		res, _ := ioutil.ReadAll(resp.Body)

		return res, nil
	}
	Log.Infof("push request body , %s", string(data))
	res, err := PostFunc(data)
	return res, err
}

func FormatBlackSaveData(blkList define.BlackListInfo) ([]byte, error) {
	var invokeRequest define.InvokeRequest
	t := GetTranDateTime()
	blkList.CreatTime = t
	val, _ := json.Marshal(blkList)
	invokeRequest.Value = string(val)
	invokeRequest.Key = fmt.Sprintf("%s-%s", blkList.CommData.UserId, blkList.CommData.UserName)
	return json.Marshal(invokeRequest)
}

func BlackListEncrypt(data string, key string) ([]byte, error) {
	var edReq define.EncryptDataRequest
	edReq.Method = define.CHAINSQL_ENCRYPT
	edReq.Param.Data = data
	edReq.Param.PubKey = key
	message, _ := json.Marshal(edReq)

	res, err := SendChainSqlMessage(message)
	if err != nil {
		return nil, fmt.Errorf("chainSql encrypt error : %s", err.Error())
	}

	return res, nil
}

func BlackListTransfer(addr string) error {
	var req define.TransferRequest
	var response define.TransferResponse
	req.Method = define.CHAINSQL_TRANSFERACCOUNT
	req.Param.DestAddress = addr
	message, _ := json.Marshal(req)

	res, err := SendChainSqlMessage(message)
	if err != nil {
		Log.Errorf("sendsql message error , %s", err.Error())
		return fmt.Errorf("chainSql encrypt error : %s", err.Error())
	}

	err = json.Unmarshal(res, &response)
	if err != nil {
		Log.Errorf("unmarshal response error , %s", err.Error())
		return fmt.Errorf("chainSql unmarshal response error : %s", err.Error())
	}

	if response.ResponseCode != http.StatusOK {
		Log.Errorf("chainsql response error , errcode %d", response.ResponseCode)
		return fmt.Errorf("chainsql response error , errcode %d", response.ResponseCode)
	}

	return nil
}
func BlackListDescrypt(res define.PaymentResponseCC, pk string) (string, error) {
	eData, _ := base64.StdEncoding.DecodeString(res.EncryptData)
	eKey, _ := base64.StdEncoding.DecodeString(res.EncryptKey)
	dataByte, err := DecryptData(eData, eKey, pk)
	if err != nil {
		return "", err
	}
	return string(dataByte), nil
}
func FormatBlackSaveDataByCrpto(blkList define.BlackListInfo) ([]byte, error) {
	var invokeRequest define.InvokeRequest
	t := GetTranDateTime()
	blkList.CreatTime = t
	blkList.CommData.ListStatus = uint64(time.Now().UnixNano() / 1000000)
	/*
	   key := GenerateKey(32)
	   cryptoData, err := AesEncrypt([]byte(blkList.SpecialData), key)
	   if err != nil{
	       return nil, fmt.Errorf("AesEncrypt data error : %s", err.Error())
	   }
	   blkList.SpecialData = base64.StdEncoding.EncodeToString(cryptoData)
	   path := define.CRYPTO_PATH + "enrollment.cert"
	   cert, err := ReadFile(path)
	   if err != nil{
	       return nil, fmt.Errorf("AesEncrypt data error : %s", err.Error())
	   }

	   cryptoKey, err := EciesEncrypt(key, cert)
	   if err != nil {
	       return nil, fmt.Errorf("EciesEncrypt  key error : %s", err.Error())
	   }
	   blkList.EncryKey = base64.StdEncoding.EncodeToString(cryptoKey)*/
	//	chanRes, err := BlackListEncrypt(blkList.SpecialData, blkList.CommData.PaymentPubKey)
	//	if err == nil {
	//		var edRes define.EncryptDataResponse
	//		err1 := json.Unmarshal(chanRes, &edRes)
	//		if err1 != nil {
	//			return nil, fmt.Errorf("encrypt error : %s", err1.Error())
	//		}
	//		blkList.SpecialData = edRes.EncryptData
	//		blkList.EncryKey = edRes.EncryptKey
	//	}
	EnDataByte, EnKeyByte, err := EncryptData([]byte(blkList.SpecialData), blkList.CommData.PaymentPubKey)
	if err != nil {
		return nil, err
	}
	blkList.SpecialData = base64.StdEncoding.EncodeToString(EnDataByte)
	blkList.EncryKey = base64.StdEncoding.EncodeToString(EnKeyByte)
	val, _ := json.Marshal(blkList)
	invokeRequest.Value = string(val)
	invokeRequest.Key = fmt.Sprintf("%s-%s", blkList.CommData.UserId, blkList.CommData.UserName)
	return json.Marshal(invokeRequest)
}

func FormatMaterialsVerify(m define.MaterialsInfo) define.VerifiedBase {
	var vb define.VerifiedBase
	vb.OrgID = m.OrgInfo.OrgID
	vb.Orgname = m.OrgInfo.EnterpriseInfo.Orgname
	vb.CreateTime = m.OrgInfo.CreateTime
	vb.VerifiedDate = m.VerifiedDate
	vb.UploadTimes = m.UploadTimes
	vb.QueryState = m.QueryState
	vb.Suggestion = m.Suggestion
	return vb
}
