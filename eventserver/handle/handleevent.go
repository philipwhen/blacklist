package handle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"strconv"

	"github.com/peersafe/poc_blacklist/apiserver/define"
	eutils "github.com/peersafe/poc_blacklist/eventserver/utils"

	"github.com/gogo/protobuf/proto"
	listener "github.com/hyperledger/fabric-sdk-go-peersafe/pkg/block-listener"
	pkg_common "github.com/hyperledger/fabric-sdk-go-peersafe/pkg/common"
	cp "github.com/hyperledger/fabric-sdk-go-peersafe/pkg/common/peer"
	"github.com/hyperledger/fabric/core/ledger/util"
	"github.com/hyperledger/fabric/core/scc/qscc"
	"github.com/hyperledger/fabric/protos/common"
	pc "github.com/hyperledger/fabric/protos/common"
	protos_peer "github.com/hyperledger/fabric/protos/peer"
	"github.com/hyperledger/fabric/protos/utils"
)

type FilterHandler func(*protos_peer.ChaincodeEvent) (interface{}, bool)

const (
	fileSaveName = "current.info"
	SendUrl      = "http://127.0.0.1:8888/blacklist/senddata"
)

var (
	currentBlockHeight uint64
	info               = new(BlockInfo)
)

func SetBlockInfo(info *BlockInfo) error {
	//make a json
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}

	//write into file
	f, err := os.Create(fileSaveName)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	} else if err == nil {
		err = f.Close()
	}
	return err
}

func GetBlockInfo() error {
	//read from file
	data, err := ioutil.ReadFile(fileSaveName)
	if err != nil {
		return err
	}

	//parse from json
	err = json.Unmarshal(data, info)
	return err
}

func CheckAndRecoverEvent(peerClients []*cp.PeerClient, chainID string, filterHandler FilterHandler, fromListen chan BlockInfoAll) {
	var currentBlockNum uint64 = 0

	if filterHandler == nil {
		logger.Errorf("The filter handler is null!")
		return
	}

	err := GetBlockInfo()
	if err != nil {
		logger.Error("get block info from current.info file failed:", err.Error())
		logger.Warning("Set the info.blockNum to be 0")
		info.Block_number = 0
	}
	currentBlockNum = info.Block_number
	logger.Info("the block height is", currentBlockHeight, "and has processed", currentBlockNum)

	//Retrieve the transactions, which were written during eventserver is not running
	for ; currentBlockNum < currentBlockHeight; currentBlockNum++ {
		block, err := GetBlockByNumber(peerClients, chainID, currentBlockNum)
		if err != nil {
			logger.Error(err.Error())
			return
		}
		txsFltr := util.TxValidationFlags(block.Metadata.Metadata[pc.BlockMetadataIndex_TRANSACTIONS_FILTER])
		var blockNum = block.Header.Number
		for txIndex, r := range block.Data.Data {
			if currentBlockNum == info.Block_number {
				if txIndex <= info.Tx_index {
					continue
				}
			}

			tx, _ := listener.GetTxPayload(r)
			if tx != nil {
				chdr, err := utils.UnmarshalChannelHeader(tx.Header.ChannelHeader)
				if err != nil {
					logger.Errorf("Error extracting channel header")
					continue
				}
				var isInvalidTx = txsFltr.IsInvalid(txIndex)
				event, err := listener.GetChainCodeEvents(tx)
				if err != nil {
					if isInvalidTx {
						logger.Errorf("Received invalidTx from channel '%s': %s", chdr.ChannelId, err.Error())
						continue
					} else {
						logger.Errorf("Received failed from channel '%s':%s", chdr.ChannelId, err.Error())
						continue
					}
				}
				//match the corresponding chainID
				if len(chainID) != 0 && chdr.ChannelId != chainID {
					continue
				}
				//filter msg from chiancode event
				var msg, ok = filterHandler(event)
				//send msg to the message queue
				if ok {
					typestring := reflect.TypeOf(msg).String()
					if typestring == "define.BlacklistKeyData" {
						err = ParseBlockInfo(msg.(define.BlacklistKeyData))
						if err != nil {
							logger.Errorf("parse block info failed: %s", err.Error())
							continue
						}
						err = SetBlockInfo(&BlockInfo{Block_number: blockNum, Tx_index: txIndex})
						if err != nil {
							logger.Errorf("Set block info failed: %s", err.Error())
							continue
						}
					} else {
						err = ProcessPayment(msg.(define.PaymentResponseCC))
						if err != nil {
							logger.Errorf("process payment failed: %s", err.Error())
							continue
						}
					}

				}
			}
		}
	}

	//Handle the transactions from listen module
	for {
		select {
		case blockInfo := <-fromListen:
			if blockInfo.BlockType == 1 {
				err = ParseBlockInfo(blockInfo.MsgInfo.(define.BlacklistKeyData))
				if err != nil {
					logger.Errorf("parse block info failed: %s", err.Error())
					continue
				}
				err = SetBlockInfo(&BlockInfo{Block_number: blockInfo.Block_number, Tx_index: blockInfo.Tx_index})
				if err != nil {
					logger.Errorf("Set block info failed: %s", err.Error())
					continue
				}
			} else {
				err = ProcessPayment(blockInfo.MsgInfo.(define.PaymentResponseCC))
				if err != nil {
					logger.Errorf("process payment failed: %s", err.Error())
					continue
				}
			}

		}
	}
}

func GetBlockByNumber(peerClients []*cp.PeerClient, chainId string, blockNum uint64) (*common.Block, error) {
	strBlockNum := strconv.FormatUint(blockNum, 10)
	args := []string{qscc.GetBlockByNumber, chainId, strBlockNum}
	resps, err := pkg_common.CreateAndProcessProposal(peerClients, "qscc", chainId, args, common.HeaderType_ENDORSER_TRANSACTION)
	if err != nil {
		return nil, fmt.Errorf("Can not get installed chaincodes, %s", err.Error())
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

func GetBlockHeight(peerClients []*cp.PeerClient, chainId string) bool {
	args := []string{qscc.GetChainInfo, chainId}
	resps, err := pkg_common.CreateAndProcessProposal(peerClients, "qscc", chainId, args, common.HeaderType_ENDORSER_TRANSACTION)
	if err != nil {
		logger.Error("Can not get installed chaincodes", err.Error())
		return false
	} else if len(resps) == 0 {
		logger.Error("Get empty responce from peer!")
		return false
	}
	data := resps[0].Response.Payload
	var chaininfo = new(common.BlockchainInfo)
	err = proto.Unmarshal(data, chaininfo)
	if err != nil {
		logger.Error("Unmarshal from payload failed:", err.Error())
		return false
	}

	currentBlockHeight = chaininfo.Height
	logger.Info("the current block height is", currentBlockHeight)

	return true
}

/* ##############################################
* description: 解析区块信息，由交易ID得到黑名单统计字段的相对变化量
* input:       Type：	黑名单类型（"TotalCnt"、"1~7"、"2018-3"）
*			   ListCnt：黑名单数量
* output:      error信息
* ###############################################*/
func ParseBlockInfo(blacklistKeyData interface{}) error {
	var err error
	blKeyData, ok := blacklistKeyData.(define.BlacklistKeyData)
	if !ok {
		logger.Error("blacklistKeyData was not type of *define.BlacklistKeyData")
		return nil
	}
	blacklistCntList := []eutils.BlackListCnt{}
	for blacklistCntType, blacklistCntValue := range blKeyData.BlackListCntInfo.BlackListCnt {
		bl := eutils.BlackListCnt{}
		bl.Type = blacklistCntType
		bl.ListCnt = uint64(blacklistCntValue)
		blacklistCntList = append(blacklistCntList, bl)
	}
	err = UpdateSqlite(blacklistCntList)
	if err != nil {
		logger.Errorf("operate sqlite3 error, %s", err.Error())
		return err
	}
	return nil
}
func ProcessPayment(paymentRequest interface{}) error {
	var err error
	pres, ok := paymentRequest.(define.PaymentResponseCC)
	if !ok {
		logger.Error("paymentRequest was not type of *define.PaymentResponseCC")
		return nil
	}
	dbFile := "./blacklist.db" //sqlite3数据库名字
	dbFileExist, err := eutils.FileOrDirectoryExist(dbFile)
	if err != nil {
		return err
	}
	if !dbFileExist {
		return err
	}
	d, err := eutils.ConnectDB("sqlite3", dbFile)
	if err != nil {
		return err
	}
	defer d.DisConnectDB()

	privateKey, err := d.QueryAddressTable(pres.DestinationAddress)
	if privateKey == "" {
		return err
	}

	request := define.PaymentParam{}
	request.Destination = pres.DestinationAddress
	request.EncryptData = pres.EncryptData
	request.EncryptKey = pres.EncryptKey
	request.SourceSecret = privateKey
	request.PubKey = pres.PubKey
	request.Source = pres.SourceAddress
	message, err := json.Marshal(request)
	if err != nil {
		logger.Errorf("marshal request error , %s", err.Error())
		return err
	}
	_, err = SendApiServerMessage(message, SendUrl)
	if err != nil {
		logger.Errorf("sendurl message error , %s", err.Error())
		return fmt.Errorf("sendurl message error : %s", err.Error())
	}
	return nil
}
func SendApiServerMessage(data []byte, destUrl string) ([]byte, error) {
	PostFunc := func(data []byte) ([]byte, error) {
		req, err := http.NewRequest("POST", destUrl, bytes.NewBuffer(data))
		if err != nil {
			logger.Errorf("New post request error , %s", err.Error())
			return []byte("empty"), err
		}
		req.Header.Set("Content-Type", "application/json")
		//req.Header.Set("Content-Type", "application/json; charset=UTF-8")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			logger.Errorf("client do error , %s", err.Error())
			return []byte("empty"), err
		}
		defer resp.Body.Close()
		res, _ := ioutil.ReadAll(resp.Body)

		return res, nil
	}
	logger.Infof("push request body , %s", string(data))
	res, err := PostFunc(data)
	return res, err
}

/* ##############################################
* description: 更新sqlite3数据库
* input:       Type：	黑名单类型（"TotalCnt"、"1~7"、"2018-3"）
*			   ListCnt：黑名单数量
* output:      error信息
* ###############################################*/
func UpdateSqlite(blacklistCntList []eutils.BlackListCnt) error {
	dbFile := "./blacklist.db" //sqlite3数据库名字
	dbFileExist, err := eutils.FileOrDirectoryExist(dbFile)
	if err != nil {
		logger.Errorf("check file exist or not error, %s", err.Error())
		return err
	}
	if !dbFileExist {
		_, err := os.Create(dbFile) // 创建数据库
		if err != nil {
			logger.Errorf("create dbfile error,  %s", err.Error())
			return err
		}
	}
	d, err := eutils.ConnectDB("sqlite3", dbFile) // 连接数据库
	if err != nil {
		logger.Errorf("connectdb err, %s", err.Error())
		return err
	}
	defer d.DisConnectDB()
	if !dbFileExist {
		err := d.CreateTable() // 创建表
		if err != nil {
			logger.Errorf("create table err, %s", err.Error())
			return err
		}
		err = d.InsertTable(blacklistCntList)
		if err != nil {
			logger.Errorf("insert table err, %s", err.Error())
			return err
		}
	}
	blCntList, err := d.QueryTable() // 查询数据库
	if err != nil {
		logger.Errorf("query table err, %s", err.Error())
		return err
	}
	insertBlackListCntList := []eutils.BlackListCnt{}
	updateBlackListCntList := []eutils.BlackListCnt{}
	for _, blacklistCnt := range blacklistCntList {
		notExistFlag := true
		for _, blCnt := range blCntList {
			if blacklistCnt.Type == blCnt.Type {
				bl := eutils.BlackListCnt{}
				bl.Id = blCnt.Id
				bl.Type = blCnt.Type
				bl.ListCnt = blCnt.ListCnt + blacklistCnt.ListCnt
				updateBlackListCntList = append(updateBlackListCntList, bl)
				notExistFlag = false
				break
			}
		}
		if notExistFlag {
			insertBlackListCntList = append(insertBlackListCntList, blacklistCnt)
		}
	}
	err = d.InsertTable(insertBlackListCntList) // 插入数据库
	if err != nil {
		logger.Errorf("insert table err, %s", err.Error())
		return err
	}
	err = d.UpdateTable(updateBlackListCntList) // 更新数据库
	if err != nil {
		logger.Errorf("update table err, %s", err.Error())
		return err
	}
	return nil
}
