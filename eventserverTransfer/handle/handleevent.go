package handle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"net/http"
	"time"

	"github.com/peersafe/poc_blacklist/apiserver/define"
	eutils "github.com/peersafe/poc_blacklist/eventserverTransfer/utils"

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
	"golang.org/x/net/context"
	"golang.org/x/time/rate"
)

type FilterHandler func(*protos_peer.ChaincodeEvent) (interface{}, bool)

const (
	fileSaveName = "current.info"
)

var (
	currentBlockHeight uint64
	info               = new(BlockInfo)
	ChainsqlUrl string
	ChainsqlRateLimit float64  // 每秒并发上限
	ChainsqlTimeout time.Duration  // 默认单位秒
	Sqlite3DbPath string
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

	limiter := rate.NewLimiter(rate.Limit(ChainsqlRateLimit), int(ChainsqlRateLimit))  // 第一个是限速多少，第二个是给多少token

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

			ctx, _ := context.WithTimeout(context.Background(), ChainsqlTimeout * time.Second)  // 超时后退出
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
					limiter.WaitN(context.Background(), 1)  // 有token就继续，没有就等待。
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
				}
			}
			select {
			case <- ctx.Done():
				logger.Error("Wait chainsql timeout")
				goto RetrieveTxEnd
			default:
				continue
			}
		}
	}
	RetrieveTxEnd:

	//Handle the transactions from listen module
	for {
		select {
		case blockInfo := <-fromListen:
			ctx, _ := context.WithTimeout(context.Background(), ChainsqlTimeout * time.Second)  // 超时后退出
			limiter.WaitN(context.Background(), 1)  // 有token就继续，没有就等待。
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
			select {
			case <- ctx.Done():
				logger.Error("Wait chainsql timeout")
				continue
			default:
				continue
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
	for _,  blacklistUniqueKey := range blKeyData.BlackListCntInfo.AddListUniqueKey {
		addr := blKeyData.BlkLists[blacklistUniqueKey].CommData.PaymentAddr
		err = ChainsqlPay(addr)
		if err != nil {
			logger.Errorf("ChiansqlPay error, %s", err.Error())
			return err
		}
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

/* ##############################################
* description: 更新sqlite3数据库
* input:       Type：	黑名单类型（"TotalCnt"、"1~7"、"2018-3"）
*			   ListCnt：黑名单数量
* output:      error信息
* ###############################################*/
func UpdateSqlite(blacklistCntList []eutils.BlackListCnt) error {
	// dbFile := "./blacklist.db"  //sqlite3数据库名字
	dbFile := Sqlite3DbPath
	dbFileExist, err := eutils.FileOrDirectoryExist(dbFile)
	if err != nil {
        logger.Errorf("check file exist or not error, %s", err.Error())
		return err
	}
	if !dbFileExist {
		_, err := os.Create(dbFile)		// 创建数据库
		if err != nil {
            logger.Errorf("create dbfile error,  %s", err.Error())
            return err
		}
	}
	d, err := eutils.ConnectDB("sqlite3", dbFile)	// 连接数据库
	if err != nil {
        logger.Errorf("connectdb err, %s", err.Error())
		return err
	}
	defer d.DisConnectDB()
	if !dbFileExist {
        err := d.CreateTable()	// 创建表
        if err != nil {
            logger.Errorf("create table err, %s", err.Error())
            return err
		}
	}
	blCntList, err := d.QueryTable()	// 查询数据库
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
	err = d.InsertTable(insertBlackListCntList)		// 插入数据库
	if err != nil {
		logger.Errorf("insert table err, %s", err.Error())
		return err
	}
	err = d.UpdateTable(updateBlackListCntList)		// 更新数据库
	if err != nil {
		logger.Errorf("update table err, %s", err.Error())
		return err
	}
	return nil
}

func SendChainSqlMessage(data []byte, destUrl string) ([]byte, error) {
	PostFunc := func(data []byte) ([]byte, error) {
		req, err := http.NewRequest("POST", destUrl, bytes.NewBuffer(data))
		if err != nil {
			logger.Errorf("New post request error , %s", err.Error())
			return []byte("empty"), err
		}
		//req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")

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

func ChainsqlPay(addr string) error {
	var chainsqlPayReq define.ChainsqlPayRequest
	var payParams define.PayParams
	var transactionInfo define.Transaction
	var amountInfo define.AmountInfo

	var response define.TransferResponse

	amountInfo.Currency = "SND"
	amountInfo.Value = "10"
	amountInfo.Issuer = "zHb9CJAWyB4zj91VRWn96DkukG4bwdtyTh"
	transactionInfo.TransactionType = "Payment"
	transactionInfo.Account = "zHb9CJAWyB4zj91VRWn96DkukG4bwdtyTh"
	transactionInfo.Destination = addr
	transactionInfo.Amount = amountInfo

	payParams.Offline = false
	payParams.Secret = "xnoPBzXtMeMyMHUVTgbuqAfg1SUTb"
	payParams.Tx_json = transactionInfo
	chainsqlPayReq.Method = "submit"
	// chainsqlPayReq.Params[0] = payParams
	chainsqlPayReq.Params = append(chainsqlPayReq.Params, payParams)
	chainsqlPayReq.Id = 1
	message, err := json.Marshal(chainsqlPayReq)
	if err != nil {
		logger.Errorf("marshal request error , %s", err.Error())
		return err
	}
	res, err := SendChainSqlMessage(message, ChainsqlUrl)
	if err != nil {
		logger.Errorf("sendsql message error , %s", err.Error())
		return fmt.Errorf("chainSql encrypt error : %s", err.Error())
	}
	err = json.Unmarshal(res, &response)
	if err != nil {
		logger.Errorf("unmarshal response error , %s", err.Error())
		return fmt.Errorf("chainSql unmarshal response error : %s", err.Error())
	}
	if response.Result.Engine_result_code != define.CHAINSQL_PAY_RESULT {
		logger.Errorf("chainsql response error , errcode %d", response.Result.Engine_result_code)
		return fmt.Errorf("chainsql response error , errcode %d", response.Result.Engine_result_code)
	}

	return nil
}
