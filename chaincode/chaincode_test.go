package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	api_def "github.com/peersafe/poc_blacklist/apiserver/define"
	"github.com/peersafe/poc_blacklist/chaincode/define"
	//	"github.com/peersafe/poc_blacklist/chaincode/handler"
	butils "github.com/hyperledger/fabric/bccsp/utils"
)

func TestHandler_UpLoad(t *testing.T) {
	scc := new(BillChaincode)
	stub := shim.NewMockStub("ex02", scc)
	//	bb := scc.Init(stub)
	//	if bb.Status != shim.OK {
	//		t.FailNow()
	//	}
	//	res := stub.MockInit("1", [][]byte{})
	//	if res.Status != shim.OK {
	//		fmt.Println("Init failed", string(res.Message))
	//		t.FailNow()
	//	}
	blk := &api_def.BlackListInfo{}
	blk.CommData.UserId = "11116"
	blk.CommData.UserName = "aab"
	blk.CommData.ListUniqueKey = "002"
	blk.CommData.ListType = "2"
	blk.CommData.PaymentAddr = "zEQz3Kkepn5e3uywrQ7cyD4qAFjZ3pX5qK"
	blk.CommData.PaymentPubKey = "cBQrcDYrN7Kcv8bUaRAavnE8oCTkRwb5NHn6H1CMyjMpHBB5Tgv2"
	blk.CommData.ListStatus = 0
	blk.CommData.FabricTxId = ""
	blk.CreatTime.Year = "2018"
	blk.CreatTime.Month = "04"
	blk.CreatTime.Day = "11"
	blk.CreatTime.Hour = "16"
	blk.CreatTime.Minute = "50"
	blk.CreatTime.Second = "50"
	blk.SpecialData = "adsfsafasdff"
	blk.EncryKey = "cBQrcDYrN7Kcv8bUaRAavnE8oCTkRwb5NHn6H1CMyjMpHBB5Tgv2"

	request := define.InvokeRequest{}
	tmp, _ := json.Marshal(blk)
	request.Value = string(tmp)
	request.Key = "11116aab"
	args := make([]string, 2)
	args[0] = "Upload_blacklist"
	tmp, _ = json.Marshal(request)
	args[1] = string(tmp)
	t.Log(args[0])
	t.Log(args[1])
	nArgs := define.NormalArgs{}
	var tmpargs [3]string
	tmpargs[0] = args[0]
	tmpargs[1] = args[0]
	tmpargs[2] = args[1]
	nArgs.Args = tmpargs[:]
	tmp1, _ := json.Marshal(nArgs)
	t.Log(string(tmp1))
	res := stub.MockInvoke("1", [][]byte{[]byte(args[0]), []byte(args[0]), []byte(args[1])})
	if res.Status != shim.OK {
		fmt.Println("Invoke failed", string(res.Message))
		t.FailNow()
	}
	//	_, _ = handler.Uploadblacklist(stub, "upload", args)

	//	request.Key = "11116aab22"
	//	tmp, _ = json.Marshal(request)
	//	args[1] = string(tmp)
	//	_, _ = handler.Uploadblacklist(stub, "upload", args)

}
func TestHandler_GetBalance(t *testing.T) {
	scc := new(BillChaincode)
	stub := shim.NewMockStub("ex02", scc)

	blk := &api_def.BlackListInfo{}
	blk.CommData.UserId = "11116"
	blk.CommData.UserName = "aab"
	blk.CommData.ListUniqueKey = "002"
	blk.CommData.ListType = "2"
	blk.CommData.PaymentAddr = "zEQz3Kkepn5e3uywrQ7cyD4qAFjZ3pX5qK"
	blk.CommData.PaymentPubKey = "cBQrcDYrN7Kcv8bUaRAavnE8oCTkRwb5NHn6H1CMyjMpHBB5Tgv2"
	blk.CommData.ListStatus = 0
	blk.CommData.FabricTxId = ""
	blk.CreatTime.Year = "2018"
	blk.CreatTime.Month = "04"
	blk.CreatTime.Day = "11"
	blk.CreatTime.Hour = "16"
	blk.CreatTime.Minute = "50"
	blk.CreatTime.Second = "50"
	blk.SpecialData = "adsfsafasdff"
	blk.EncryKey = "cBQrcDYrN7Kcv8bUaRAavnE8oCTkRwb5NHn6H1CMyjMpHBB5Tgv2"

	request := define.InvokeRequest{}
	tmp, _ := json.Marshal(blk)
	request.Value = string(tmp)
	request.Key = "11116aab"
	args := make([]string, 2)
	args[0] = "Upload_blacklist"
	tmp, _ = json.Marshal(request)
	args[1] = string(tmp)

	res := stub.MockInvoke("1", [][]byte{[]byte(args[0]), []byte(args[0]), []byte(args[1])})
	if res.Status != shim.OK {
		fmt.Println("Invoke failed", string(res.Message))
		t.FailNow()
	}

	balancerequest := define.BalanceQueryRequest{}
	balancerequest.Addresses = make([]string, 2)
	balancerequest.Addresses[0] = "zEQz3Kkepn5e3uywrQ7cyD4qAFjZ3pX5qK"
	balancerequest.Addresses[1] = "zEQz3Kkepn5e3uywrQ7cyD4qAFjZ3pX5qK1"
	balanceargs := make([]string, 2)
	balanceargs[0] = "GetBalance"
	tmp, _ = json.Marshal(balancerequest)
	balanceargs[1] = string(tmp)
	nArgs := define.NormalArgs{}
	var tmpargs [3]string
	tmpargs[0] = balanceargs[0]
	tmpargs[1] = balanceargs[0]
	tmpargs[2] = balanceargs[1]
	nArgs.Args = tmpargs[:]
	tmp1, _ := json.Marshal(nArgs)
	t.Log(string(tmp1))
	res = stub.MockInvoke("1", [][]byte{[]byte(balanceargs[0]), []byte(balanceargs[0]), []byte(balanceargs[1])})
	if res.Status != shim.OK {
		fmt.Println("Invoke failed", string(res.Message))
		t.FailNow()
	}

	blk.CommData.PaymentAddr = "zEQz3Kkepn5e3uywrQ7cyD4qAFjZ3pX5qK1"
	tmp, _ = json.Marshal(blk)
	request.Value = string(tmp)
	request.Key = "11116aab22"
	tmp, _ = json.Marshal(request)
	args[1] = string(tmp)
	res = stub.MockInvoke("2", [][]byte{[]byte(args[0]), []byte(args[0]), []byte(args[1])})
	if res.Status != shim.OK {
		fmt.Println("Invoke failed", string(res.Message))
		t.FailNow()
	}

	res = stub.MockInvoke("1", [][]byte{[]byte(balanceargs[0]), []byte(balanceargs[0]), []byte(balanceargs[1])})
	if res.Status != shim.OK {
		fmt.Println("Invoke failed", string(res.Message))
		t.FailNow()
	}
}

func TestHandler_Payment(t *testing.T) {
	scc := new(BillChaincode)
	stub := shim.NewMockStub("ex02", scc)

	blk := &api_def.BlackListInfo{}
	blk.CommData.UserId = "11116"
	blk.CommData.UserName = "aab"
	blk.CommData.ListUniqueKey = "002"
	blk.CommData.ListType = "2"
	blk.CommData.PaymentAddr = "AMJhMtAQu/Je4dfKDn8H7VhOVP0B/jk8Tg=="
	blk.CommData.PaymentPubKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEI3lhlLVPm2AzPW5Tb8DyEJdqqLCeVsoS3JFQ7VQ5Vdsn+Ty+4LkA5RckFiphl9fXu8P1rR/ZARSy50HRAzlYQA=="
	blk.CommData.ListStatus = 0
	blk.CommData.FabricTxId = ""
	blk.CreatTime.Year = "2018"
	blk.CreatTime.Month = "04"
	blk.CreatTime.Day = "11"
	blk.CreatTime.Hour = "16"
	blk.CreatTime.Minute = "50"
	blk.CreatTime.Second = "50"
	blk.SpecialData = "adsfsafasdff"
	blk.EncryKey = "cBQrcDYrN7Kcv8bUaRAavnE8oCTkRwb5NHn6H1CMyjMpHBB5Tgv2"

	request := define.InvokeRequest{}
	tmp, _ := json.Marshal(blk)
	request.Value = string(tmp)
	request.Key = "11116aab"
	args := make([]string, 2)
	args[0] = "Upload_blacklist"
	tmp, _ = json.Marshal(request)
	args[1] = string(tmp)
	res := stub.MockInvoke("1", [][]byte{[]byte(args[0]), []byte(args[0]), []byte(args[1])})
	if res.Status != shim.OK {
		fmt.Println("Invoke failed", string(res.Message))
		t.FailNow()
	}
	blk.CommData.UserId = "11116000"
	blk.CommData.UserName = "aab000"
	blk.CommData.PaymentAddr = "AP3fb16h0K5unSubQILJO1gXQa4X3sq4Zw=="
	blk.CommData.PaymentPubKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETgzVXIVyimLgSqCRm4oLPncBYAWRDz7tn/GFHxiYXTpS6hYdqXmYXISIMyn1uSkZRvSlKYFwtOsKQiiCYfCPRA=="
	tmp, _ = json.Marshal(blk)
	request.Value = string(tmp)
	request.Key = "11116aab22"
	tmp, _ = json.Marshal(request)
	args[1] = string(tmp)
	res = stub.MockInvoke("2", [][]byte{[]byte(args[0]), []byte(args[0]), []byte(args[1])})
	if res.Status != shim.OK {
		fmt.Println("Invoke failed", string(res.Message))
		t.FailNow()
	}
	args[0] = "Payment"
	//res = stub.MockInvoke("2", [][]byte{[]byte(args[0]), []byte(args[0]), []byte(args[1])})
	payrequest := define.PaymentRequest{}
	paymentparam := define.PaymentParam{}
	paymentparam.SourceAddress = "AP3fb16h0K5unSubQILJO1gXQa4X3sq4Zw=="
	paymentparam.PubKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETgzVXIVyimLgSqCRm4oLPncBYAWRDz7tn/GFHxiYXTpS6hYdqXmYXISIMyn1uSkZRvSlKYFwtOsKQiiCYfCPRA=="
	paymentparam.DestinationAddress = "AMJhMtAQu/Je4dfKDn8H7VhOVP0B/jk8Tg=="
	paymentparam.EncryptData = "adsfsafasdff"
	paymentparam.EncryptKey = "cBQrcDYrN7Kcv8bUaRAavnE8oCTkRwb5NHn6H1CMyjMpHBB5Tgv2"
	tmp, _ = json.Marshal(paymentparam)
	payrequest.Param = string(tmp)

	der, _ := base64.StdEncoding.DecodeString("MHcCAQEEIEwXnmo6M1+ZXZa6c7xzXKY6Ng3vx6OJ1jObuaIGOabRoAoGCCqGSM49AwEHoUQDQgAETgzVXIVyimLgSqCRm4oLPncBYAWRDz7tn/GFHxiYXTpS6hYdqXmYXISIMyn1uSkZRvSlKYFwtOsKQiiCYfCPRA==")
	skey, _ := butils.DERToPrivateKey(der)
	paramSHA256 := sha256.Sum256([]byte(payrequest.Param))
	SR, SS, _ := ecdsa.Sign(rand.Reader, skey.(*ecdsa.PrivateKey), paramSHA256[:])
	tmp2, _ := sw.MarshalECDSASignature(SR, SS)
	ss := base64.StdEncoding.EncodeToString(tmp2)
	payrequest.Signature = ss
	tmp, _ = json.Marshal(payrequest)
	args[1] = string(tmp)
	res = stub.MockInvoke("3", [][]byte{[]byte(args[0]), []byte(args[0]), []byte(args[1])})

	if res.Status != shim.OK {
		fmt.Println("Invoke failed", string(res.Message))
		t.FailNow()
	}

	balancerequest := define.BalanceQueryRequest{}
	balancerequest.Addresses = make([]string, 2)
	balancerequest.Addresses[0] = "AP3fb16h0K5unSubQILJO1gXQa4X3sq4Zw=="
	balancerequest.Addresses[1] = "AMJhMtAQu/Je4dfKDn8H7VhOVP0B/jk8Tg=="
	balanceargs := make([]string, 2)
	balanceargs[0] = "GetBalance"
	tmp, _ = json.Marshal(balancerequest)
	balanceargs[1] = string(tmp)
	res = stub.MockInvoke("1", [][]byte{[]byte(balanceargs[0]), []byte(balanceargs[0]), []byte(balanceargs[1])})
	if res.Status != shim.OK {
		fmt.Println("Invoke failed", string(res.Message))
		t.FailNow()
	}

}
