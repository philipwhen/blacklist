package peer

import (
	"fmt"
	cu "github.com/hyperledger/fabric-sdk-go-peersafe/pkg/common/utils"
	pkg_config "github.com/hyperledger/fabric-sdk-go-peersafe/pkg/config"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/protos/peer"
	"golang.org/x/net/context"
	"sync"
)

type PeerClient struct {
	pool    *cu.Pool
	MspId   string
	Primary bool
}

var peerClients []*PeerClient
var mutexGet sync.Mutex

func InitPeerClient() error {
	mutexGet.Lock()
	defer mutexGet.Unlock()

	var tlsEnabled = pkg_config.IsTLSEnabled()

	//create the peers pool
	peerConfigs, err := pkg_config.GetPeersConfig()
	if err != nil {
		return fmt.Errorf("Error GetPeersConfig: %s\n", err)
	}
	for _, c := range peerConfigs {
		peerInfo, err := cu.NewClient(c.Address, c.TLS.Certificate, c.TLS.ServerHostOverride, tlsEnabled)
		if err != nil {
			return fmt.Errorf("Get handler client info failed:%s", err.Error())
		}
		pool := &PeerClient{
			pool: cu.NewPool(20, func() (interface{}, error) {
				mutexGet.Lock()
				defer mutexGet.Unlock()
				cli, err := GetEndorserClient(peerInfo)
				if err != nil {
					err = fmt.Errorf("Get endorser client failed:%s", err.Error())
				}
				return cli, err
			}),
			MspId:   c.LocalMspId,
			Primary: c.Primary,
		}
		peerClients = append(peerClients, pool)
	}
	return nil
}

func GetPeerClients(mspID string, onlyPrimary bool) (clients []*PeerClient) {
	for _, client := range peerClients {
		if (onlyPrimary == false || (onlyPrimary && client.Primary)) && (mspID == "" || client.MspId == mspID) {
			clients = append(clients, client)
		}
	}
	return
}

func (pc *PeerClient) ProcessProposal(signedProp *peer.SignedProposal, reuse bool) (*peer.ProposalResponse, error) {
	ret, err := pc.pool.Get(reuse)
	if err != nil {
		return nil, err
	}
	if client, ok := ret.(EndorserClient); ok {
		var proposalResp *peer.ProposalResponse
		proposalResp, err = client.ProcessProposal(context.Background(), signedProp)
		if err != nil {
			err = fmt.Errorf("proposal failed (err: %s)", err.Error())
		} else if proposalResp == nil {
			err = fmt.Errorf("proposal failed (err: %s)", "nil proposal response")
		} else if proposalResp.Response.Status != 0 && proposalResp.Response.Status != 200 {
			err = fmt.Errorf("proposal failed (err: bad proposal response %d)", proposalResp.Response.Status)
		}
		if reuse {
			if err == nil {
				defer pc.pool.Put(client)
			} else if _, ok := pc.pool.DelPart(client); ok {
				client.Close()
			}
		} else {
			if err != nil {
				defer client.Close()
			}
		}
		if err != nil {
			return nil, err
		} else if proposalResp == nil {
			return nil, fmt.Errorf("ProcessProposal on client failed")
		} else if proposalResp.Response.Status != shim.OK {
			return nil, fmt.Errorf(proposalResp.Response.Message)
		}
		return proposalResp, nil
	}
	return nil, fmt.Errorf("Get peer client failed!")
}
