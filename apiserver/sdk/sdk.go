package sdk

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/gogo/protobuf/proto"
	listener "github.com/hyperledger/fabric-sdk-go-peersafe/pkg/block-listener"
	"github.com/hyperledger/fabric-sdk-go-peersafe/pkg/chaincode"
	pkg_common "github.com/hyperledger/fabric-sdk-go-peersafe/pkg/common"
	"github.com/hyperledger/fabric-sdk-go-peersafe/pkg/common/orderer"
	"github.com/hyperledger/fabric-sdk-go-peersafe/pkg/common/peer"
	"github.com/hyperledger/fabric-sdk-go-peersafe/pkg/common/user"
	"github.com/hyperledger/fabric/core/scc/qscc"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/ledger/rwset"
	"github.com/hyperledger/fabric/protos/ledger/rwset/kvrwset"
	propeer "github.com/hyperledger/fabric/protos/peer"
	proutils "github.com/hyperledger/fabric/protos/utils"
	"github.com/peersafe/poc_blacklist/apiserver/define"
	"github.com/peersafe/poc_blacklist/apiserver/utils"
	"github.com/spf13/viper"
	"golang.org/x/crypto/sha3"
)

// SDKHanlder sdk handler
type SDKHanlder struct {
	handler *chaincode.Handler
}

type BlockData struct {
	FabricBlockData   string
	FabricBlockPre    string
	FabricBlockHash   string
	FabricBlockHeight uint64
	EventMap          map[string]*propeer.ChaincodeEvent
}

// Handler sdk handler
var Handler SDKHanlder

const EMPT_STRING = "    "

func InitSDK(path, name string) error {
	err := pkg_common.InitSDK(path, name)
	channelId := viper.GetString("chaincode.id.chainID")
	ccName := viper.GetString("chaincode.id.name")
	Handler.handler = chaincode.NewHandler(channelId, ccName)

	return err
}

// GetSDK get sdk handler
func GetSDK() *SDKHanlder {
	return &Handler
}

// GetTxId invoke cc
func (sdk *SDKHanlder) GetTxId() (string, []byte, error) {
	return user.GenerateTxId()
}

// Invoke invoke cc
func (sdk *SDKHanlder) Invoke(txId string, nonce []byte, trackId, function string, carrier map[string]string, request []byte) (string, error) {
	peerClients := peer.GetPeerClients("", false)
	ordererClients := orderer.GetOrdererClients()

	_, err := sdk.handler.Invoke(peerClients, ordererClients, nonce, carrier, false, nil, function, trackId, string(request))

	return txId, err
}

func (sdk *SDKHanlder) PeerKeepalive(function string) bool {
	peerClients := peer.GetPeerClients("", true)
	//The last two parameters is redundant in this function, just because the chaincode operation must have two parameters in the current.
	response, _, err := sdk.handler.Query(peerClients, nil, function, "reduPara", "reduPara")
	if err != nil {
		fmt.Println(err)
		return false
	} else {
		keepaliveResult := string(response[0].Response.Payload)
		if keepaliveResult == "Reached" {
			return true
		} else {
			return false
		}
	}
}

func (sdk *SDKHanlder) QueryData(trackId, function string, carrier map[string]string, request string) (define.QueryContents, *define.ResponseStatus, error) {
	var data []byte
	responseData := define.QueryResponse{}
	responseData.Payload = &data
	var retValue define.QueryContents
	peerClients := peer.GetPeerClients("", true)
	response, _, err := sdk.handler.Query(peerClients, carrier, function, trackId, request)
	if err != nil {
		responseData.ResponseStatus.StatusCode = 1
		responseData.ResponseStatus.StatusMsg = err.Error()
		utils.Log.Errorf("query error :%s", err.Error())
	} else {
		responseData.ResponseStatus.StatusCode = 0
		responseData.ResponseStatus.StatusMsg = "SUCCESS"

		utils.Log.Debugf("sdk query : %s", string(response[0].Response.Payload))
		err = json.Unmarshal(response[0].Response.Payload, &responseData)
		if err != nil {
			responseData.ResponseStatus.StatusCode = 1
			responseData.ResponseStatus.StatusMsg = err.Error()
			utils.Log.Errorf("sdk unmarshal error :%s", err.Error())
			return retValue, &responseData.ResponseStatus, err
		}

		if responseData.ResponseStatus.StatusCode != 0 {
			utils.Log.Errorf("sdk unmarshal error :%s", responseData.ResponseStatus.StatusMsg)
			err = errors.New(responseData.ResponseStatus.StatusMsg)
			return retValue, &responseData.ResponseStatus, err
		}
		if len(data) == 0 {
			retValue.Payload = nil
		} else {
			retValue.Payload = data
		}
	}

	return retValue, &responseData.ResponseStatus, err

}

func (sdk *SDKHanlder) QueryDslData(trackId, function string, carrier map[string]string, request string) (define.QueryContents, *define.ResponseStatus, error) {
	var data []string
	responseData := define.QueryResponse{}
	responseData.Payload = &data
	var retValue define.QueryContents
	peerClients := peer.GetPeerClients("", true)
	response, _, err := sdk.handler.Query(peerClients, carrier, function, trackId, request)
	if err != nil {
		responseData.ResponseStatus.StatusCode = 1
		responseData.ResponseStatus.StatusMsg = err.Error()
		utils.Log.Errorf("query error :%s", err.Error())
	} else {
		responseData.ResponseStatus.StatusCode = 0
		responseData.ResponseStatus.StatusMsg = "SUCCESS"

		utils.Log.Debugf("sdk query : %s", string(response[0].Response.Payload))
		err = json.Unmarshal(response[0].Response.Payload, &responseData)
		if err != nil {
			responseData.ResponseStatus.StatusCode = 1
			responseData.ResponseStatus.StatusMsg = err.Error()
			utils.Log.Errorf("sdk unmarshal error :%s", err.Error())
			return retValue, &responseData.ResponseStatus, err
		}

		if responseData.ResponseStatus.StatusCode != 0 {
			utils.Log.Errorf("sdk unmarshal error :%s", responseData.ResponseStatus.StatusMsg)
			err = errors.New(responseData.ResponseStatus.StatusMsg)
			return retValue, &responseData.ResponseStatus, err
		}

		retValue.Payload = data
	}

	return retValue, &responseData.ResponseStatus, err

}

func checkAndRemove(keys *[]string, key string) bool {
	for i, val := range *keys {
		if key == val {
			*keys = append((*keys)[:i], (*keys)[i+1:]...)
			return true
		}
	}
	return false
}

func GetBlockByTxids(txids []string) (map[string]*BlockData, error) {
	var getBlockByTxid = func(txid string) (*common.Block, error) {
		chainId := viper.GetString("chaincode.id.chainID")
		peerClients := peer.GetPeerClients("", true)
		args := []string{qscc.GetBlockByTxID, chainId, txid}
		resps, err := pkg_common.CreateAndProcessProposal(peerClients, "qscc", chainId, args, common.HeaderType_ENDORSER_TRANSACTION)
		if err != nil {
			return nil, fmt.Errorf("Can not get installed chaincodes", err.Error())
		} else if len(resps) == 0 {
			return nil, fmt.Errorf("Get empty responce from peer!")
		}
		data := resps[0].Response.Payload
		var block = new(common.Block)
		err = proto.Unmarshal(data, block)
		if err != nil {
			return nil, fmt.Errorf("Unmarshal from payload failed: %s", err.Error())
		}
		return block, nil
	}

	var blockInfos map[string]*BlockData
	blockInfos = make(map[string]*BlockData)

	for _, txid := range txids {
		if len(txid) == 0 {
			return blockInfos, nil
		}
		var block, err = getBlockByTxid(txid)
		if err != nil {
			return blockInfos, err
		}

		blockHash := fmt.Sprintf("%x", block.Header.DataHash)

		if len(blockHash) == 0 {
			continue
		}

		_, exist := blockInfos[blockHash]

		if exist == false {
			blockInfos[blockHash] = new(BlockData)
			blockInfos[blockHash].FabricBlockData = block.String()
			blockInfos[blockHash].FabricBlockPre = fmt.Sprintf("%x", block.Header.PreviousHash)
			blockInfos[blockHash].FabricBlockHash = blockHash
			blockInfos[blockHash].FabricBlockHeight = block.Header.Number
			blockInfos[blockHash].EventMap = make(map[string]*propeer.ChaincodeEvent)
		}

		for _, r := range block.Data.Data {
			tx, _ := listener.GetTxPayload(r)
			if tx != nil {
				chdr, err := proutils.UnmarshalChannelHeader(tx.Header.ChannelHeader)
				if err != nil {
					fmt.Println("Error extracting channel header")
					continue
				}
				events, err := GetChainCodeEvents(tx)
				if err != nil {
					fmt.Println("Received failed from channel '%s':%s", chdr.ChannelId, err.Error())
					continue
				}

				for _, y := range events {
					if checkAndRemove(&txids, y.TxId) {
						blockInfos[blockHash].EventMap[y.TxId] = y
					}
				}
			}
		}
	}
	return blockInfos, nil
}

func analysisCCEvent(payload []byte) ([]string, error) {
	responseData := define.QueryResponse{}
	var messages []string
	responseData.Payload = &messages
	if err := json.Unmarshal(payload, &responseData); err != nil {
		return messages, err
	}
	return messages, nil
}

// getChainCodeEvents parses block events for chaincode events associated with individual transactions
func GetChainCodeEvents(payload *common.Payload) ([]*propeer.ChaincodeEvent, error) {
	chdr, err := proutils.UnmarshalChannelHeader(payload.Header.ChannelHeader)
	if err != nil {
		return nil, fmt.Errorf("Could not extract channel header from envelope, err %s", err)
	}

	if common.HeaderType(chdr.Type) == common.HeaderType_ENDORSER_TRANSACTION {
		tx, err := proutils.GetTransaction(payload.Data)
		if err != nil {
			return nil, fmt.Errorf("Error unmarshalling transaction payload for block event: %s", err)
		}

		var events []*propeer.ChaincodeEvent
		for _, r := range tx.Actions {
			chaincodeActionPayload, err := proutils.GetChaincodeActionPayload(r.Payload)
			if err != nil {
				return nil, fmt.Errorf("Error unmarshalling transaction action payload for block event: %s", err)
			}
			propRespPayload, err := proutils.GetProposalResponsePayload(chaincodeActionPayload.Action.ProposalResponsePayload)
			if err != nil {
				return nil, fmt.Errorf("Error unmarshalling proposal response payload for block event: %s", err)
			}
			caPayload, err := proutils.GetChaincodeAction(propRespPayload.Extension)
			if err != nil {
				return nil, fmt.Errorf("Error unmarshalling chaincode action for block event: %s", err)
			}
			ccEvent, err := proutils.GetChaincodeEvents(caPayload.Events)
			events = append(events, ccEvent)
		}

		if events != nil {
			return events, nil
		}
	}
	return nil, errors.New("No events found")
}

func calHash(msg []byte) string {
	hash := sha3.New224()
	hash.Write(msg)
	value := hash.Sum(nil)
	return fmt.Sprintf("%x", value)
}

func SprintfChaincodeProposalPayload(empt string, cpl *propeer.ChaincodeProposalPayload) (string, error) {
	var str string
	eptStr := empt
	str += eptStr + fmt.Sprintf("ChaincodeProposalPayload------------------------------B\r\n")
	eptStr1 := eptStr + EMPT_STRING
	str += eptStr1 + fmt.Sprintf("Input------------------------------B\r\n")
	eptStr2 := eptStr1 + EMPT_STRING
	str += eptStr2 + fmt.Sprintf("ChaincodeInvocationSpec------------------------------B\r\n")
	eptStr3 := eptStr2 + EMPT_STRING
	ccInvokSpec := &propeer.ChaincodeInvocationSpec{}
	err := proto.Unmarshal(cpl.Input, ccInvokSpec)
	if err != nil {
		return err.Error(), fmt.Errorf("Unmarshal ChaincodeInvocationSpec failed, err %s", err)
	}
	ccSpec := ccInvokSpec.ChaincodeSpec
	if ccSpec != nil {
		str += eptStr3 + fmt.Sprintf("ChaincodeSpec------------------------------B\r\n")
		eptStr4 := eptStr3 + EMPT_STRING
		str += eptStr4 + fmt.Sprintf("Type : %d\r\n", ccSpec.Type)
		if ccSpec.ChaincodeId != nil {
			str += eptStr4 + fmt.Sprintf("ChaincodeId------------------------------B\r\n")
			eptStr5 := eptStr4 + EMPT_STRING
			str += eptStr5 + fmt.Sprintf("Path : %s\r\n", ccSpec.ChaincodeId.Path)
			str += eptStr5 + fmt.Sprintf("Name : %s\r\n", ccSpec.ChaincodeId.Name)
			str += eptStr5 + fmt.Sprintf("Version : %s\r\n", ccSpec.ChaincodeId.Version)
			str += eptStr4 + fmt.Sprintf("ChaincodeId------------------------------E\r\n")
		}

		if ccSpec.Input != nil {
			str += eptStr4 + fmt.Sprintf("Input : %v\r\n", ccSpec.Input)
		}

		str += eptStr4 + fmt.Sprintf("Timeout : %d\r\n", ccSpec.Timeout)
		str += eptStr3 + fmt.Sprintf("ChaincodeSpec------------------------------E\n")
	}
	str += eptStr3 + fmt.Sprintf("IdGenerationAlg : %s\r\n", ccInvokSpec.IdGenerationAlg)
	str += eptStr2 + fmt.Sprintf("ChaincodeInvocationSpec------------------------------E\r\n")
	str += eptStr1 + fmt.Sprintf("Input------------------------------E\r\n")

	str += eptStr1 + fmt.Sprintf("TransientMap : %v\r\n", cpl.TransientMap)

	str += eptStr + fmt.Sprintf("ChaincodeProposalPayload------------------------------E\r\n")

	return str, nil
}

func SprintfEndorsement(empt string, eds *propeer.Endorsement) (string, error) {
	var str string
	eptStr := empt
	str += eptStr + fmt.Sprintf("Endorsement------------------------------B\r\n")
	eptStr1 := eptStr + EMPT_STRING
	str += eptStr1 + fmt.Sprintf("Endorser : %s\r\n", string(eds.Endorser))
	str += eptStr1 + fmt.Sprintf("Signature : %v\r\n", eds.Signature)
	str += eptStr + fmt.Sprintf("Endorsement------------------------------E\r\n")

	return str, nil
}

func SprintfKVReads(empt string, kvread *kvrwset.KVRead) (string, error) {
	var str string
	eptStr := empt
	str += eptStr + fmt.Sprintf("KVRead------------------------------B\r\n")
	eptStr1 := eptStr + EMPT_STRING
	str += eptStr1 + fmt.Sprintf("Key : %s\r\n", kvread.Key)
	if kvread.Version != nil {
		str += eptStr1 + fmt.Sprintf("Version------------------------------B\r\n")
		eptStr2 := eptStr1 + EMPT_STRING
		str += eptStr2 + fmt.Sprintf("BlockNum : %v\r\n", kvread.Version.BlockNum)
		str += eptStr2 + fmt.Sprintf("TxNum : %v\r\n", kvread.Version.TxNum)
		str += eptStr1 + fmt.Sprintf("Version------------------------------E\r\n")
	}
	str += eptStr + fmt.Sprintf("KVRead------------------------------E\r\n")

	return str, nil
}

func SprintfKVRWset(empt string, kvRWSet *kvrwset.KVRWSet) (string, error) {
	var str string
	eptStr := empt
	str += eptStr + fmt.Sprintf("Reads------------------------------B\r\n")
	eptStr1 := eptStr + EMPT_STRING
	for _, kvread := range kvRWSet.Reads {
		nStr, err := SprintfKVReads(eptStr1, kvread)
		if err != nil {
			return err.Error(), fmt.Errorf("SprintfPropResResults error, err %s", err)
		}
		str += nStr
	}
	str += eptStr + fmt.Sprintf("Reads------------------------------E\r\n")

	str += eptStr + fmt.Sprintf("RangeQuerysInfo------------------------------B\r\n")
	eptStr2 := eptStr + EMPT_STRING
	for _, queryInfo := range kvRWSet.RangeQueriesInfo {
		str += eptStr2 + fmt.Sprintf("RangeQueryInfo------------------------------B\r\n")
		eptStr3 := eptStr2 + EMPT_STRING
		str += eptStr3 + fmt.Sprintf("StartKey : %s\r\n", queryInfo.StartKey)
		str += eptStr3 + fmt.Sprintf("EndKey : %s\r\n", queryInfo.EndKey)
		str += eptStr3 + fmt.Sprintf("ItrExhausted : %v\r\n", queryInfo.ItrExhausted)
		rqRawReads, ok := queryInfo.ReadsInfo.(*kvrwset.RangeQueryInfo_RawReads)
		if ok {
			str += eptStr3 + fmt.Sprintf("RawReads------------------------------B\r\n")
			eptStr4 := eptStr3 + EMPT_STRING
			if rqRawReads.RawReads != nil {
				for _, kvread := range rqRawReads.RawReads.KvReads {
					nStr, err := SprintfKVReads(eptStr4, kvread)
					if err != nil {
						return err.Error(), fmt.Errorf("SprintfPropResResults error, err %s", err)
					}
					str += nStr
				}
			}
			str += eptStr3 + fmt.Sprintf("RawReads------------------------------E\r\n")
		}

		readsMHs, ok := queryInfo.ReadsInfo.(*kvrwset.RangeQueryInfo_ReadsMerkleHashes)
		if ok {
			str += eptStr3 + fmt.Sprintf("ReadsMerkleHashes------------------------------B\r\n")
			eptStr5 := eptStr3 + EMPT_STRING
			readMerkHashs := readsMHs.ReadsMerkleHashes
			if readMerkHashs != nil {
				str += eptStr5 + fmt.Sprintf("MaxDegree : %d\r\n", readMerkHashs.MaxDegree)
				str += eptStr5 + fmt.Sprintf("MaxLevel : %d\r\n", readMerkHashs.MaxLevel)
				str += eptStr5 + fmt.Sprintf("MaxDegree : %v\r\n", readMerkHashs.MaxLevelHashes)
			}
			str += eptStr3 + fmt.Sprintf("ReadsMerkleHashes------------------------------E\r\n")
		}
		str += eptStr2 + fmt.Sprintf("RangeQueryInfo------------------------------E\r\n")
	}
	str += eptStr + fmt.Sprintf("RangeQuerysInfo------------------------------E\r\n")

	str += eptStr + fmt.Sprintf("Writes------------------------------B\r\n")
	eptStr6 := eptStr + EMPT_STRING
	for _, kvwrite := range kvRWSet.Writes {
		str += eptStr6 + fmt.Sprintf("KVWrite------------------------------B\r\n")
		eptStr7 := eptStr6 + EMPT_STRING
		str += eptStr7 + fmt.Sprintf("Key : %s\r\n", kvwrite.Key)
		str += eptStr7 + fmt.Sprintf("IsDelete : %v\r\n", kvwrite.IsDelete)
		str += eptStr7 + fmt.Sprintf("Value : %s\r\n", string(kvwrite.Value))
		str += eptStr6 + fmt.Sprintf("KVWrite------------------------------E\r\n")
	}
	str += eptStr + fmt.Sprintf("Writes------------------------------E\r\n")
	return str, nil
}

func SprintfPropResResults(empt string, txRWSet *rwset.TxReadWriteSet) (string, error) {
	var str string
	eptStr := empt
	str += eptStr + fmt.Sprintf("DataModel : %d\r\n", txRWSet.DataModel)
	str += eptStr + fmt.Sprintf("NsRwset------------------------------B\r\n")
	eptStr1 := eptStr + EMPT_STRING
	for _, rwset := range txRWSet.NsRwset {
		str += eptStr1 + fmt.Sprintf("NsReadWriteSet------------------------------B\r\n")
		eptStr2 := eptStr1 + EMPT_STRING
		str += eptStr2 + fmt.Sprintf("Namespace : %d\r\n", rwset.Namespace)
		str += eptStr2 + fmt.Sprintf("KVRWSet------------------------------B\r\n")
		kvRWSet := &kvrwset.KVRWSet{}
		err := proto.Unmarshal(rwset.Rwset, kvRWSet)
		if err != nil {
			return err.Error(), fmt.Errorf("Unmarshal KVRWSet failed, err %s", err)
		}
		eptStr3 := eptStr2 + EMPT_STRING
		nStr, err := SprintfKVRWset(eptStr3, kvRWSet)
		if err != nil {
			return err.Error(), fmt.Errorf("SprintfPropResResults error, err %s", err)
		}
		str += nStr
		str += eptStr2 + fmt.Sprintf("KVRWSet------------------------------E\r\n")
		str += eptStr1 + fmt.Sprintf("NsReadWriteSet------------------------------E\r\n")

	}
	str += eptStr + fmt.Sprintf("NsRwset------------------------------E\r\n")

	return str, nil
}

func SprintfProposalResponsePayload(empt string, propRes *propeer.ProposalResponsePayload) (string, error) {
	var str string
	eptStr := empt
	str += eptStr + fmt.Sprintf("ProposalHash : %v\r\n", propRes.ProposalHash)
	str += eptStr + fmt.Sprintf("Extension------------------------------B\r\n")
	chaincodeAction := &propeer.ChaincodeAction{}
	err := proto.Unmarshal(propRes.Extension, chaincodeAction)
	if err != nil {
		return err.Error(), fmt.Errorf("Unmarshal ChaincodeAction failed, err %s", err)
	}

	eptStr1 := eptStr + EMPT_STRING
	str += eptStr1 + fmt.Sprintf("chaincodeAction------------------------------B\r\n")
	eptStr2 := eptStr1 + EMPT_STRING
	str += eptStr2 + fmt.Sprintf("Results------------------------------S\r\n")
	eptStr3 := eptStr2 + EMPT_STRING
	str += eptStr3 + fmt.Sprintf("TxReadWriteSet------------------------------B\r\n")
	protoTxRWSet := &rwset.TxReadWriteSet{}
	err = proto.Unmarshal(chaincodeAction.Results, protoTxRWSet)
	if err != nil {
		return err.Error(), fmt.Errorf("Unmarshal TxReadWriteSet failed, err %s", err)
	}

	eptStr4 := eptStr3 + EMPT_STRING
	nStr, err := SprintfPropResResults(eptStr4, protoTxRWSet)
	if err != nil {
		return err.Error(), fmt.Errorf("SprintfPropResResults error, err %s", err)
	}
	str += nStr

	str += eptStr3 + fmt.Sprintf("TxReadWriteSet------------------------------E\r\n")
	str += eptStr2 + fmt.Sprintf("Results------------------------------E\r\n")
	str += eptStr2 + fmt.Sprintf("Events------------------------------B\r\n")
	chaincodeEvent := &propeer.ChaincodeEvent{}
	err = proto.Unmarshal(chaincodeAction.Events, chaincodeEvent)
	if err != nil {
		return err.Error(), fmt.Errorf("Unmarshal ChaincodeEvent failed, err %s", err)
	}

	eptStr4 = eptStr2 + EMPT_STRING
	str += eptStr4 + fmt.Sprintf("ChaincodeId : %s\r\n", chaincodeEvent.ChaincodeId)
	str += eptStr4 + fmt.Sprintf("TxId : %s\r\n", chaincodeEvent.TxId)
	str += eptStr4 + fmt.Sprintf("EventName : %s\r\n", chaincodeEvent.EventName)
	str += eptStr4 + fmt.Sprintf("Payload : %s\r\n", string(chaincodeEvent.Payload))
	str += eptStr2 + fmt.Sprintf("Events------------------------------E\r\n")

	if chaincodeAction.Response != nil {
		str += eptStr2 + fmt.Sprintf("Response------------------------------B\r\n")
		eptStr5 := eptStr2 + EMPT_STRING
		str += eptStr5 + fmt.Sprintf("Status : %d\r\n", chaincodeAction.Response.Status)
		str += eptStr5 + fmt.Sprintf("Message : %s\r\n", chaincodeAction.Response.Message)
		str += eptStr5 + fmt.Sprintf("Payload : %s\r\n", string(chaincodeAction.Response.Payload))
		str += eptStr2 + fmt.Sprintf("Response------------------------------E\r\n")
	}

	if chaincodeAction.ChaincodeId != nil {
		str += eptStr2 + fmt.Sprintf("ChaincodeId------------------------------B\r\n")
		eptStr6 := eptStr2 + EMPT_STRING
		str += eptStr6 + fmt.Sprintf("Path : %s\r\n", chaincodeAction.ChaincodeId.Path)
		str += eptStr6 + fmt.Sprintf("Name : %s\r\n", chaincodeAction.ChaincodeId.Name)
		str += eptStr6 + fmt.Sprintf("Version : %s\r\n", chaincodeAction.ChaincodeId.Version)
		str += eptStr2 + fmt.Sprintf("ChaincodeId------------------------------E\r\n")
	}

	str += eptStr1 + fmt.Sprintf("chaincodeAction------------------------------E\r\n")

	str += eptStr + fmt.Sprintf("Extension------------------------------E\r\n")

	return str, nil
}

func SprintfAction(empt string, ccEnAct *propeer.ChaincodeEndorsedAction) (string, error) {
	var str string
	eptStr := empt
	str += eptStr + fmt.Sprintf("ChaincodeEndorsedAction------------------------------B\r\n")
	eptStr1 := eptStr + EMPT_STRING
	str += eptStr1 + fmt.Sprintf("ProposalResponsePayload------------------------------B\r\n")
	propRes := &propeer.ProposalResponsePayload{}
	err := proto.Unmarshal(ccEnAct.ProposalResponsePayload, propRes)
	if err != nil {
		return err.Error(), fmt.Errorf("Unmarshal ProposalResponsePayload failed, err %s", err)
	}

	eptStr2 := eptStr1 + EMPT_STRING
	nStr, err := SprintfProposalResponsePayload(eptStr2, propRes)
	if err != nil {
		return err.Error(), fmt.Errorf("SprintfEndorsement error, err %s", err)
	}
	str += nStr
	str += eptStr1 + fmt.Sprintf("ProposalResponsePayload------------------------------E\r\n")

	str += eptStr1 + fmt.Sprintf("Endorsements------------------------------B\r\n")
	eptStr3 := eptStr1 + EMPT_STRING
	for _, eds := range ccEnAct.Endorsements {
		nStr, err = SprintfEndorsement(eptStr3, eds)
		if err != nil {
			return err.Error(), fmt.Errorf("SprintfEndorsement error, err %s", err)
		}
		str += nStr
	}

	str += eptStr1 + fmt.Sprintf("Endorsements------------------------------E\r\n")
	str += eptStr + fmt.Sprintf("ChaincodeEndorsedAction------------------------------E\r\n")

	return str, nil
}

func SprintfEnvelopePayloadHead(empt string, hdr *common.Header) (string, error) {
	var str string
	eptStr := empt
	/*channelHead*/
	str += eptStr + fmt.Sprintf("ChannelHeader------------------------------B\r\n")
	eptStr1 := eptStr + EMPT_STRING
	chdr := &common.ChannelHeader{}
	err := proto.Unmarshal(hdr.ChannelHeader, chdr)
	if err != nil {
		return err.Error(), fmt.Errorf("UnmarshalChannelHeader failed, err %s", err)
	}
	str += eptStr1 + fmt.Sprintf("Type : %d\r\n", chdr.Type)
	str += eptStr1 + fmt.Sprintf("Version : %d\r\n", chdr.Version)
	str += eptStr1 + fmt.Sprintf("Timestamp------------------------------B\r\n")
	eptStr2 := eptStr1 + EMPT_STRING
	str += eptStr2 + fmt.Sprintf("Seconds : %v\r\n", chdr.Timestamp.Seconds)
	str += eptStr2 + fmt.Sprintf("Nanos : %v\r\n", chdr.Timestamp.Nanos)
	str += eptStr1 + fmt.Sprintf("Timestamp------------------------------E\r\n")
	str += eptStr1 + fmt.Sprintf("ChannelId: %s\r\n", chdr.ChannelId)
	str += eptStr1 + fmt.Sprintf("TxId: %s\r\n", chdr.TxId)
	str += eptStr1 + fmt.Sprintf("Epoch: %v\r\n", chdr.Epoch)
	str += eptStr1 + fmt.Sprintf("ChaincodeHeaderExtension------------------------------B\r\n")
	ccHdrExt := &propeer.ChaincodeHeaderExtension{}
	err = proto.Unmarshal(chdr.Extension, ccHdrExt)
	if err != nil {
		return err.Error(), fmt.Errorf("UnmarshalChannelHeader failed, err %s", err)
	}
	eptStr3 := eptStr1 + EMPT_STRING
	str += eptStr3 + fmt.Sprintf("PayloadVisibility : %s\r\n", string(ccHdrExt.PayloadVisibility))
	if ccHdrExt.ChaincodeId != nil {
		str += eptStr3 + fmt.Sprintf("ChaincodeId------------------------------B\r\n")
		eptStr4 := eptStr3 + EMPT_STRING
		str += eptStr4 + fmt.Sprintf("Path : %s\r\n", ccHdrExt.ChaincodeId.Path)
		str += eptStr4 + fmt.Sprintf("Name : %s\r\n", ccHdrExt.ChaincodeId.Name)
		str += eptStr4 + fmt.Sprintf("Version : %s\r\n", ccHdrExt.ChaincodeId.Version)
		str += eptStr3 + fmt.Sprintf("ChaincodeId------------------------------E\r\n")
	}
	str += eptStr1 + fmt.Sprintf("ChaincodeHeaderExtension------------------------------E\r\n")
	str += eptStr + fmt.Sprintf("ChannelHeader------------------------------E\r\n")

	/*signatureheader*/

	str += eptStr + fmt.Sprintf("SignatureHeader------------------------------B\r\n")
	sghdr := &common.SignatureHeader{}
	err = proto.Unmarshal(hdr.SignatureHeader, sghdr)
	if err != nil {
		return err.Error(), fmt.Errorf("Could not extract transaction header, err %s", err)
	}
	eptStr5 := eptStr + EMPT_STRING
	str += eptStr5 + fmt.Sprintf("Creator : %s\r\n", string(sghdr.Creator))
	str += eptStr5 + fmt.Sprintf("Nonce : %v\r\n", sghdr.Nonce)
	str += eptStr + fmt.Sprintf("SignatureHeader------------------------------E\r\n")
	return str, nil
}

func SprintfEnvelopePayloadTransactions(empt string, trans *propeer.TransactionAction) (string, error) {
	var str string
	eptStr := empt
	str += eptStr + fmt.Sprintf("Transaction------------------------------B\r\n")
	eptStr1 := eptStr + EMPT_STRING
	str += eptStr1 + fmt.Sprintf("Header------------------------------B\r\n")
	eptStr2 := eptStr1 + EMPT_STRING
	str += eptStr2 + fmt.Sprintf("SignatureHeader------------------------------B\r\n")
	sghdr := &common.SignatureHeader{}
	err := proto.Unmarshal(trans.Header, sghdr)
	if err != nil {
		return err.Error(), fmt.Errorf("Could not extract transaction header, err %s", err)
	}
	eptStr3 := eptStr2 + EMPT_STRING
	str += eptStr3 + fmt.Sprintf("Creator : %s\r\n", string(sghdr.Creator))
	str += eptStr3 + fmt.Sprintf("Nonce : %v\r\n", sghdr.Nonce)
	str += eptStr2 + fmt.Sprintf("SignatureHeader------------------------------E\r\n")
	str += eptStr1 + fmt.Sprintf("Header------------------------------E\r\n")

	str += eptStr1 + fmt.Sprintf("Payload------------------------------B\r\n")
	eptStr4 := eptStr1 + EMPT_STRING
	str += eptStr4 + fmt.Sprintf("ChaincodeActionPayload------------------------------B\r\n")
	cap := &propeer.ChaincodeActionPayload{}
	err = proto.Unmarshal(trans.Payload, cap)
	if err != nil {
		return err.Error(), fmt.Errorf("Could not extract ChaincodeActionPayload, err %s", err)
	}

	ccPropPayload := &propeer.ChaincodeProposalPayload{}
	err = proto.Unmarshal(cap.ChaincodeProposalPayload, ccPropPayload)
	if err != nil {
		return err.Error(), fmt.Errorf("Could not extract ChaincodeActionPayload, err %s", err)
	}
	eptStr5 := eptStr4 + EMPT_STRING
	nStr, err := SprintfChaincodeProposalPayload(eptStr5, ccPropPayload)
	if err != nil {
		return err.Error(), fmt.Errorf("Error SprintfChaincodeProposalPayload(%s)", err)
	}
	str += nStr

	if cap.Action != nil {
		nStr, err := SprintfAction(eptStr5, cap.Action)
		if err != nil {
			return err.Error(), fmt.Errorf("Error SprintfChaincodeProposalPayload(%s)", err)
		}
		str += nStr
	}

	str += eptStr4 + fmt.Sprintf("ChaincodeActionPayload------------------------------E\r\n")
	str += eptStr1 + fmt.Sprintf("Payload------------------------------E\r\n")
	str += eptStr + fmt.Sprintf("Transaction------------------------------E\r\n")

	return str, nil
}

func SprintfEnvelope(empt string, env *common.Envelope) (string, error) {
	var str string
	eptStr := empt
	str += eptStr + fmt.Sprintf("Envelope------------------------------B\r\n")
	/*Payload*/
	eptStr1 := eptStr + EMPT_STRING
	str += eptStr1 + fmt.Sprintf("Payload------------------------------B\r\n")
	payload := &common.Payload{}
	err := proto.Unmarshal(env.Payload, payload)
	if err != nil {
		return err.Error(), fmt.Errorf("Could not extract payload from envelope, err %s", err)
	}

	/*payload-header*/
	eptStr2 := eptStr1 + EMPT_STRING
	str += eptStr2 + fmt.Sprintf("Header------------------------------B\r\n")
	eptStr3 := eptStr2 + EMPT_STRING
	nStr, err := SprintfEnvelopePayloadHead(eptStr3, payload.Header)
	if err != nil {
		return err.Error(), fmt.Errorf("Error Sprintf envelope payload head(%s)", err)
	}
	str += nStr
	str += eptStr2 + fmt.Sprintf("Header------------------------------E\r\n")

	chdr, err := proutils.UnmarshalChannelHeader(payload.Header.ChannelHeader)
	if err != nil {
		return err.Error(), fmt.Errorf("Could not extract channel header from envelope, err %s", err)
	}

	/*payload-Data-Transaction*/
	str += eptStr2 + fmt.Sprintf("Data------------------------------B\r\n")
	if common.HeaderType(chdr.Type) == common.HeaderType_ENDORSER_TRANSACTION {
		tx := &propeer.Transaction{}
		err := proto.Unmarshal(payload.Data, tx)
		if err != nil {
			return err.Error(), fmt.Errorf("Error Sprintf envelope payload transaction(%s)", err)
		}
		eptStr4 := eptStr2 + EMPT_STRING
		str += eptStr4 + fmt.Sprintf("Transactions------------------------------B\r\n")
		for _, r := range tx.Actions {
			eptStr5 := eptStr4 + EMPT_STRING
			nStr, err := SprintfEnvelopePayloadTransactions(eptStr5, r)
			if err != nil {
				return err.Error(), fmt.Errorf("Error Sprintf envelope payload transaction(%s)", err)
			}
			str += nStr
		}
		str += eptStr4 + fmt.Sprintf("Transactions------------------------------E\r\n")
	}
	str += eptStr2 + fmt.Sprintf("Data------------------------------E\r\n")

	str += eptStr1 + fmt.Sprintf("Payload------------------------------E\r\n")

	/*Signature*/
	str += eptStr1 + fmt.Sprintf("Signature : %v\r\n", env.Signature)

	str += eptStr + fmt.Sprintf("Envelope------------------------------E\r\n")

	return str, nil
}

/*common.Metadata
    Value      []byte
	Signatures []*MetadataSignature
*/
func SprintfMetada(empt string, md *common.Metadata) (string, error) {
	var str string
	eptStr := empt
	config := &common.LastConfig{}
	err := proto.Unmarshal(md.Value, config)
	if err == nil {
		str += eptStr + fmt.Sprintf("Value : %v\r\n", config.Index)
	}

	for _, sgn := range md.Signatures {
		str += eptStr + fmt.Sprintf("MetadataSignature------------------------------B\r\n")
		eptStr1 := eptStr + EMPT_STRING
		str += eptStr1 + fmt.Sprintf("SignatureHeader------------------------------B\r\n")
		sghdr := &common.SignatureHeader{}
		err = proto.Unmarshal(sgn.SignatureHeader, sghdr)
		if err != nil {
			return err.Error(), fmt.Errorf("Could not extract transaction header, err %s", err)
		}
		eptStr2 := eptStr1 + EMPT_STRING
		str += eptStr2 + fmt.Sprintf("Creator : %s\r\n", string(sghdr.Creator))
		str += eptStr2 + fmt.Sprintf("Nonce : %v\r\n", sghdr.Nonce)
		str += eptStr1 + fmt.Sprintf("SignatureHeader------------------------------E\r\n")

		str += eptStr1 + fmt.Sprintf("Signature : %v\r\n", sgn.Signature)
		str += eptStr + fmt.Sprintf("MetadataSignature------------------------------E\r\n")
	}

	return str, nil
}

/*common.Block
    Header   *BlockHeader
	Data     *BlockData
	Metadata *BlockMetadata
*/
func SprintfBlockInfo(block *common.Block) (string, error) {
	var str string
	eptStr := EMPT_STRING
	/*block header*/
	hdr := block.Header
	if hdr != nil {
		str += fmt.Sprintf("BlockHeader------------------------------B\r\n")
		str += eptStr + fmt.Sprintf("Number: %d \r\n", hdr.Number)
		str += eptStr + fmt.Sprintf("PreviousHash: %v \r\n", hdr.PreviousHash)
		str += eptStr + fmt.Sprintf("DataHash: %v \r\n", hdr.DataHash)
		str += fmt.Sprintf("BlockHeader-------------------------E\r\n")
	}

	/*block data*/
	data := block.Data
	if data != nil {
		var err error
		for _, data := range data.Data {
			env := &common.Envelope{}
			if err = proto.Unmarshal(data, env); err != nil {
				return err.Error(), fmt.Errorf("Error getting envelope(%s)", err)
			}
			str += fmt.Sprintf("BlockData------------------------------B\r\n")
			nStr, err := SprintfEnvelope(eptStr, env)
			if err != nil {
				return err.Error(), fmt.Errorf("Error Sprintf envelope(%s)", err)
			}
			str += nStr
			str += fmt.Sprintf("BlockData------------------------------E\r\n")
		}

	}

	/*metaData*/
	metaData := block.Metadata
	if metaData != nil {
		str += fmt.Sprintf("BlockMetadata------------------------------B\r\n")
		for index, metadata := range metaData.Metadata {
			if index == int(common.BlockMetadataIndex_TRANSACTIONS_FILTER) {
				txsfltr := block.Metadata.Metadata[common.BlockMetadataIndex_TRANSACTIONS_FILTER]
				str += fmt.Sprintf("Metadata2 filter : %v\r\n", txsfltr)
				continue
			}

			md := &common.Metadata{}
			err := proto.Unmarshal(metadata, md)
			if err != nil {
				continue
			}
			str += fmt.Sprintf("Metadata%d------------------------------B\r\n", index)
			nStr, err := SprintfMetada(eptStr, md)
			if err != nil {
				return err.Error(), fmt.Errorf("Error Sprintf envelope(%s)", err)
			}
			str += nStr
			str += fmt.Sprintf("Metadata%d------------------------------E\r\n", index)
		}
		str += fmt.Sprintf("BlockMetadata------------------------------E\r\n")
	}

	return str, nil
}

func GetBlockByNumber(peerClients []*peer.PeerClient, chainId string, blockNum uint64) (*common.Block, error) {
	strBlockNum := strconv.FormatUint(blockNum, 10)
	args := []string{qscc.GetBlockByNumber, chainId, strBlockNum}
	resps, err := pkg_common.CreateAndProcessProposal(peerClients, "qscc", chainId, args, common.HeaderType_ENDORSER_TRANSACTION)
	if err != nil {
		return nil, fmt.Errorf("Can not get installed chaincodes", err.Error())
	} else if len(resps) == 0 {
		return nil, fmt.Errorf("Get empty responce from peer!")
	}
	data := resps[0].Response.Payload
	var block = new(common.Block)
	err = proto.Unmarshal(data, block)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal from payload failed: %s", err.Error())
	}

	return block, nil
}

func PrintfBlockInfoByNumber(chainID string, blockNum uint64) {
	peerClients := peer.GetPeerClients("", true)
	block, err := GetBlockByNumber(peerClients, chainID, blockNum)
	if err == nil {
		str, _ := SprintfBlockInfo(block)
		fmt.Printf("%s", str)
	}
	fmt.Println("Printf block end")
}
