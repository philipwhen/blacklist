package orderer

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hyperledger/fabric-sdk-go-peersafe/pkg/common/utils"
	"github.com/hyperledger/fabric/protos/common"
)

type OrdererClient struct {
	bc         BroadcastClient
	clientInfo *utils.ClientInfo
	sync.Mutex
}

const (
	OrderReconnectCount = 3
)

var (
	broadcastClients []*OrdererClient
)

func InitBroadcastClient() error {
	orderers, err := newClients()
	if err != nil {
		return err
	}

	for _, order := range orderers {
		bc, err := GetBroadcastClient(&order)
		if err != nil {
			fmt.Println("InitBroadcastClient err")
			return err
		}
		client := &OrdererClient{
			bc:         bc,
			clientInfo: &order,
		}
		broadcastClients = append(broadcastClients, client)
	}

	return nil
}

func GetOrdererClients() []*OrdererClient {
	return broadcastClients
}

func (oc *OrdererClient) BroadcastClientSend(env *common.Envelope) error {
	oc.Lock()
	defer oc.Unlock()

	err := oc.bc.Send(env)

	if err == nil {
		return nil
	} else if strings.ContainsAny(err.Error(), "transport is closing") {
		if oc.reconnectOrder() {
			fmt.Println("reconnect to order success")
			if err = oc.bc.Send(env); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("[(oc *OrdererClient)] lost connect with order!")
		}
	} else {
		fmt.Println("[(oc *OrdererClient)] BroadcastClientSend  err: ", err)
		return err
	}

	return nil
}

func (oc *OrdererClient) Close() {
	oc.bc.Close()
}

func (oc *OrdererClient) reconnectOrder() bool {
	tryConnect := 1

	for {
		if tryConnect > OrderReconnectCount {
			return false
		}
		if bc, err := GetBroadcastClient(oc.clientInfo); err == nil {
			oc.bc.Close()
			oc.bc = bc
			return true
		} else {
			time.Sleep(time.Second)
			fmt.Println("tryconnect order failed", tryConnect)
		}
		tryConnect++
	}
}
