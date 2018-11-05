package listenevent

import (
	"fmt"

	"github.com/peersafe/poc_blacklist/eventserverTransfer/handle"

	listener "github.com/hyperledger/fabric-sdk-go-peersafe/pkg/block-listener"
	"github.com/hyperledger/fabric/core/ledger/util"
	pc "github.com/hyperledger/fabric/protos/common"
	protos_peer "github.com/hyperledger/fabric/protos/peer"
	"github.com/hyperledger/fabric/protos/utils"
	"github.com/op/go-logging"
)

var (
	logger = logging.MustGetLogger("listen-event")
)

type FilterHandler func(*protos_peer.ChaincodeEvent) (interface{}, bool)

/*
func ListenEvent(eventAddress, chainID string, filterHandler FilterHandler) error {
	notfy := listener.GetListenChannel(eventAddress, chainID)
	if notfy == nil {
		return fmt.Errorf("The Listen event notify is empty!")
	}

	if filterHandler == nil {
		return fmt.Errorf("The filter handler is null!")
	}

	for {
		select {
		case b := <-notfy:
			var block = b.Block
			txsFltr := util.TxValidationFlags(block.Metadata.Metadata[pc.BlockMetadataIndex_TRANSACTIONS_FILTER])
			//var blockNum = block.Header.Number
			for txIndex, r := range block.Data.Data {
				err := func() error {
					tx, err := listener.GetTxPayload(r)
					if tx != nil || err != nil {
						chdr, err := utils.UnmarshalChannelHeader(tx.Header.ChannelHeader)
						if err != nil {
							return fmt.Errorf("Error extracting channel header")
						}
						var isInvalidTx = txsFltr.IsInvalid(txIndex)
						event, err := listener.GetChainCodeEvents(tx)
						if err != nil {
							if isInvalidTx {
								return fmt.Errorf("Received invalidTx from channel '%s': %s", chdr.ChannelId, err.Error())
							} else {
								return fmt.Errorf("Received failed from channel '%s':%s", chdr.ChannelId, err.Error())
							}
						}
						//match the corresponding chainID
						if (len(chainID) != 0 && chdr.ChannelId != chainID) {
							return nil
						}
						//filter msg from chiancode event
						var _, ok = filterHandler(event)
						//send msg/blockNum/txIndex to handle module
						if ok {
							//logger.Infof("blockNum is %d , indexNum is %d", blockNum, txIndex)
						}
						return nil
					}
					return fmt.Errorf("Get tx payload is failed:%v, err:%v", tx, err)
				}()
				if err != nil {
					logger.Error(err.Error())
				}
			}
		}
	}
	return nil
}
*/

func ListenEvent(eventAddress, chainID string, filterHandler FilterHandler, toHandle chan handle.BlockInfoAll) error {
	notfy := listener.GetListenChannel(eventAddress, chainID)
	if notfy == nil {
		return fmt.Errorf("The Listen event notify is empty!")
	}

	if filterHandler == nil {
		return fmt.Errorf("The filter handler is null!")
	}

	for {
		select {
		case b := <-notfy:
			var block = b.Block
			txsFltr := util.TxValidationFlags(block.Metadata.Metadata[pc.BlockMetadataIndex_TRANSACTIONS_FILTER])
			var blockNum = block.Header.Number
			for txIndex, r := range block.Data.Data {
				err := func() error {
					tx, err := listener.GetTxPayload(r)
					if tx != nil || err != nil {
						chdr, err := utils.UnmarshalChannelHeader(tx.Header.ChannelHeader)
						if err != nil {
							return fmt.Errorf("Error extracting channel header")
						}
						var isInvalidTx = txsFltr.IsInvalid(txIndex)
						event, err := listener.GetChainCodeEvents(tx)
						if err != nil {
							if isInvalidTx {
								return fmt.Errorf("Received invalidTx from channel '%s': %s", chdr.ChannelId, err.Error())
							} else {
								return fmt.Errorf("Received failed from channel '%s':%s", chdr.ChannelId, err.Error())
							}
						}
						//match the corresponding chainID
						if len(chainID) != 0 && chdr.ChannelId != chainID {
							return nil
						}
						//filter msg from chiancode event
						var msg, ok = filterHandler(event)
						//send msg/blockNum/txIndex to handle module
						if ok {
							blockInfo := handle.BlockInfoAll{
								BlockInfo: handle.BlockInfo{Block_number: blockNum,
									Tx_index: txIndex},
								MsgInfo: msg,
							}
							go func() {
								toHandle <- blockInfo
							}()
						}
						return nil
					}
					return fmt.Errorf("Get tx payload is failed:%v, err:%v", tx, err)
				}()
				if err != nil {
					logger.Error(err.Error())
				}
			}
		}
	}
	return nil
}
