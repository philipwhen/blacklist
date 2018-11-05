package peer

import (
	"github.com/hyperledger/fabric-sdk-go-peersafe/pkg/common/utils"
	protos_peer "github.com/hyperledger/fabric/protos/peer"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

type EndorserClient interface {
	ProcessProposal(ctx context.Context, in *protos_peer.SignedProposal, opts ...grpc.CallOption) (*protos_peer.ProposalResponse, error)
	Close() error
}

type endorserClient struct {
	conn *grpc.ClientConn
	protos_peer.EndorserClient
}

func (e *endorserClient) Close() error {
	return e.conn.Close()
}

func GetEndorserClient(pInfo *utils.ClientInfo) (EndorserClient, error) {
	conn, err := grpc.Dial(pInfo.Url, pInfo.GrpcDialOption...)
	if err != nil {
		return nil, err
	}
	client := &endorserClient{EndorserClient: protos_peer.NewEndorserClient(conn), conn: conn}
	return client, nil
}
