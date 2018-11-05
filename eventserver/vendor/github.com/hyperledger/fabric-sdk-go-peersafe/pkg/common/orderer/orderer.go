package orderer

import (
	"errors"
	"fmt"
	"github.com/hyperledger/fabric-sdk-go-peersafe/pkg/common/utils"
	"github.com/hyperledger/fabric-sdk-go-peersafe/pkg/config"
	"github.com/hyperledger/fabric/protos/common"
	"sync"
)

type OrdererClient struct {
	pool *utils.Pool
}

var (
	broadcastClients []*OrdererClient
)

const (
	ClientReconnectCount = 3
)

func InitBroadcastClient() error {
	//create the order pool
	var tlsEnabled = config.IsTLSEnabled()
	ordererInfo, err := utils.NewClient(config.GetOrdererAddress(), config.GetOrderCaFile(), config.GetOrderServerHostOverride(), tlsEnabled)
	if err != nil {
		err = fmt.Errorf("Get handler client info failed:%s", err.Error())
		return err
	}
	var mutex sync.Mutex
	client := &OrdererClient{
		pool: utils.NewPool(20, func() (interface{}, error) {
			mutex.Lock()
			defer mutex.Unlock()
			cli, err := GetBroadcastClient(ordererInfo)
			if err != nil {
				err = fmt.Errorf("Get broadcast client failed:%s", err.Error())
			}
			return cli, err
		})}
	broadcastClients = append(broadcastClients, client)
	return nil
}

func GetOrdererClients() []*OrdererClient {
	return broadcastClients
}

func (bc *OrdererClient) BroadcastClientSend(env *common.Envelope, reuse bool) error {
	var client BroadcastClient
	for i := 0; i < ClientReconnectCount && client == nil; i++ {
		ret, err := bc.pool.Get(reuse)
		if err != nil {
			return err
		}

		var ok bool
		if client, ok = ret.(BroadcastClient); !ok {
			client = nil
		}
	}

	if client == nil {
		return errors.New("BroadcastClient get failed!")
	}

	err := client.Send(env)
	if reuse {
		if err == nil {
			defer bc.pool.Put(client)
		} else if _, ok := bc.pool.DelPart(client); ok {
			client.Close()
		}
	} else {
		if err != nil {
			defer client.Close()
		}
	}
	return err
}
