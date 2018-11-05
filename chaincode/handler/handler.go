package handler

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/hyperledger/fabric/bccsp/sw"
	butils "github.com/hyperledger/fabric/bccsp/utils"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/op/go-logging"
	api_def "github.com/peersafe/poc_blacklist/apiserver/define"
	"github.com/peersafe/poc_blacklist/chaincode/define"
	"github.com/peersafe/poc_blacklist/chaincode/utils"
)

var myLogger = logging.MustGetLogger("hanldler")

var KEEPALIVETEST = "keepAliveTest"

func init() {
	format := logging.MustStringFormatter("%{shortfile} %{time:15:04:05.000} [%{module}] %{level:.4s} : %{message}")
	backend := logging.NewLogBackend(os.Stderr, "", 0)
	backendFormatter := logging.NewBackendFormatter(backend, format)

	logging.SetBackend(backendFormatter).SetLevel(logging.DEBUG, "hanldler")
}

func Uploadblacklist(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	var err error
	var ccSaveBlk api_def.BlacklistKeyData
	request := &define.InvokeRequest{}

	if err = json.Unmarshal([]byte(args[1]), request); err != nil {
		return utils.InvokeResponse(stub, err, function, nil, false)
	}

	blk := &api_def.BlackListInfo{}
	if err = json.Unmarshal([]byte(request.Value), blk); err != nil {
		return utils.InvokeResponse(stub, err, function, nil, false)
	}

	listKey := blk.CommData.ListUniqueKey
	currentMonType := fmt.Sprintf("%s-%s", blk.CreatTime.Year, blk.CreatTime.Month)
	b, _, _ := stub.GetState(request.Key)
	//var IsUploaded bool
	if b == nil {
		ccSaveBlk.BlkLists = make(map[string]api_def.BlackListInfo)
		ccSaveBlk.BlkLists[listKey] = *blk
		ccSaveBlk.BlackListCntInfo.AddListUniqueKey = make([]string, 0)
		ccSaveBlk.BlackListCntInfo.UpdateListUniqueKey = make([]string, 0)
		ccSaveBlk.BlackListCntInfo.DeleteListUniqueKey = make([]string, 0)
		ccSaveBlk.BlackListCntInfo.BlackListCnt = make(map[string]int)
		ccSaveBlk.BlackListCntInfo.AddListUniqueKey = append(ccSaveBlk.BlackListCntInfo.AddListUniqueKey, listKey)
		ccSaveBlk.BlackListCntInfo.BlackListCnt[blk.CommData.ListType] = 1
		ccSaveBlk.BlackListCntInfo.BlackListCnt[api_def.BLACKLIST_TOTAL_COUNT] = 1
		ccSaveBlk.BlackListCntInfo.BlackListCnt[currentMonType] = 1
		//IsUploaded = true
	} else {
		if err = json.Unmarshal(b, &ccSaveBlk); err != nil {
			return utils.InvokeResponse(stub, err, function, nil, false)
		}
		ccSaveBlk.BlackListCntInfo.AddListUniqueKey = make([]string, 0)
		ccSaveBlk.BlackListCntInfo.UpdateListUniqueKey = make([]string, 0)
		ccSaveBlk.BlackListCntInfo.DeleteListUniqueKey = make([]string, 0)
		ccSaveBlk.BlackListCntInfo.BlackListCnt = make(map[string]int)
		_, ok := ccSaveBlk.BlkLists[listKey]
		if ok {
			// ccSaveBlk.BlackListCntInfo.UpdateListUniqueKey = append(ccSaveBlk.BlackListCntInfo.UpdateListUniqueKey, listKey)
			// ccSaveBlk.BlackListCntInfo.BlackListCnt[blk.CommData.ListType] = 0
			// ccSaveBlk.BlackListCntInfo.BlackListCnt[api_def.BLACKLIST_TOTAL_COUNT] = 0
			// ccSaveBlk.BlackListCntInfo.BlackListCnt[currentMonType] = 0
			err = fmt.Errorf("%s", "Blacklist already exist!")
			//IsUploaded = false
			return utils.InvokeResponse(stub, err, function, nil, false)
		} else {
			ccSaveBlk.BlackListCntInfo.AddListUniqueKey = append(ccSaveBlk.BlackListCntInfo.AddListUniqueKey, listKey)
			ccSaveBlk.BlackListCntInfo.BlackListCnt[blk.CommData.ListType] = 1
			ccSaveBlk.BlackListCntInfo.BlackListCnt[api_def.BLACKLIST_TOTAL_COUNT] = 1
			ccSaveBlk.BlackListCntInfo.BlackListCnt[currentMonType] = 1
			//IsUploaded = true
		}
		ccSaveBlk.BlkLists[listKey] = *blk
	}

	// 不能在这里直接调时间生成，各个chaincode之间这个参数值可能不一样，导致上传失败
	// ccSaveBlk.BlackListCntInfo.OperationTime = time.Now().Unix()
	// 使用在apiserver传入的时间
	operationTime := fmt.Sprintf("%s-%s-%s %s:%s:%s", blk.CreatTime.Year, blk.CreatTime.Month, blk.CreatTime.Day, blk.CreatTime.Hour, blk.CreatTime.Minute, blk.CreatTime.Second)
	ccSaveBlk.BlackListCntInfo.OperationTime = operationTime
	ccSaveBlk.DataType = api_def.DATATYPE_BLACKLIST

	val, _ := json.Marshal(ccSaveBlk)
	err = stub.PutState(request.Key, val, shim.NormalTypeValue)
	if err != nil {
		myLogger.Errorf("Uploadblacklist err: %s", err.Error())
		return utils.InvokeResponse(stub, err, function, nil, false)
	}
	//balanceRequest := define.BalanceData{}
        //balanceRequest.Address = blk.CommData.PaymentAddr
	//bValue, _, _ := stub.GetState(balanceRequest.Address)
	//if bValue == nil {
	//	InitVal := int64ToBytes(10)
	//	err = stub.PutState(balanceRequest.Address, InitVal, shim.TokenTypeValue)
	//	var buf bytes.Buffer
	//	buf.WriteString("Pubkeyof")
	//	buf.WriteString(balanceRequest.Address)
	//	_ = stub.PutState(buf.String(), []byte(blk.CommData.PaymentPubKey), shim.NormalTypeValue)
	//	if err != nil {
	//		myLogger.Errorf("Add Balance Error err: %s", err.Error())
	//		return utils.InvokeResponse(stub, err, function, nil, false)
	//	}
	//} else {
	//	NewVal := int64ToBytes(10)
	//	err = stub.PutState(balanceRequest.Address, NewVal, shim.TokenTypeValue)
	//	if err != nil {
	//		myLogger.Errorf("Add Balance Error err: %s", err.Error())
	//		return utils.InvokeResponse(stub, err, function, nil, false)
	//	}
	//}

	return utils.InvokeResponse(stub, err, function, ccSaveBlk, true)
}

func SaveData(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	var err error
	request := &define.InvokeRequest{}
	if err = json.Unmarshal([]byte(args[1]), request); err != nil {
		return utils.InvokeResponse(stub, err, function, nil, false)
	}

	err = stub.PutState(request.Key, []byte(request.Value), shim.NormalTypeValue)
	if err != nil {
		myLogger.Errorf("saveData err: %s", err.Error())
		return utils.InvokeResponse(stub, err, function, nil, false)
	}

	var list []string
	list = append(list, request.Value)
	return utils.InvokeResponse(stub, nil, function, list, true)
}
func GetBalance(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	var err error
	page := define.Page{}
	request := &define.BalanceQueryRequest{}
	response := &define.BalanceQueryResponse{}
	if err = json.Unmarshal([]byte(args[1]), request); err != nil {
		return utils.QueryResponse(err, nil, page)
	}
	response.ResultData = make([]define.BalanceData, len(request.Addresses))
	for index, address := range request.Addresses {
		bValue, _, _ := stub.GetState(address)
		response.ResultData[index].Address = address
		if bValue == nil {
			response.ResultData[index].Value = ""
		} else {
			response.ResultData[index].Value = strconv.Itoa(int(bytesToInt64(bValue)))
		}

	}
	responseByte, err := json.Marshal(response)
	if err != nil {
		return utils.QueryResponse(err, nil, page)
	}
	return utils.QueryResponse(nil, responseByte, page)
}
func Payment(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	var err error
	request := &define.PaymentRequest{}
	response := &define.PaymentResponse{}
	if err = json.Unmarshal([]byte(args[1]), request); err != nil {
		return utils.InvokeResponse(stub, err, function, nil, false)
	}
	payparam := &define.PaymentParam{}
	if err = json.Unmarshal([]byte(request.Param), payparam); err != nil {
		return utils.InvokeResponse(stub, err, function, nil, false)
	}
	//verify the public key and address
	var buf bytes.Buffer
	buf.WriteString("Pubkeyof")
	buf.WriteString(payparam.SourceAddress)
	pubByteReal, _, _ := stub.GetState(buf.String())
	if payparam.PubKey != string(pubByteReal[:]) {
		response.StatusCode = 5
		response.StatusMsg = "pubkey is wrong!"
		return utils.InvokeResponse(stub, err, function, response, false)
	}
	//generate public key
	pkdecodeBytes, err := base64.StdEncoding.DecodeString(payparam.PubKey)
	if err != nil {
		return utils.InvokeResponse(stub, err, function, nil, false)
	}
	pub, err := butils.DERToPublicKey(pkdecodeBytes)
	if err != nil {
		return utils.InvokeResponse(stub, err, function, nil, false)
	}
	//verify the signature
	//	var currentBCCSP bccsp.BCCSP
	// Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool
	//	digest, err := currentBCCSP.Hash([]byte(request.Param), &bccsp.SHAOpts{})
	//	pk, err := currentBCCSP.KeyImport(pub, &bccsp.ECDSAGoPublicKeyImportOpts{Temporary: false})
	//	valid, err := currentBCCSP.Verify(pk, []byte(request.Signature), digest, nil)
	//	valid, err := sw.verifyECDSA(&pub, []byte(request.signature), []byte(request.Param), nil)UnmarshalECDSASignature(raw []byte) (*big.Int, *big.Int, error)
	ss, _ := base64.StdEncoding.DecodeString(request.Signature)
	SR, SS, err := sw.UnmarshalECDSASignature(ss)
	paramSHA256 := sha256.Sum256([]byte(request.Param))
	valid := ecdsa.Verify(pub.(*ecdsa.PublicKey), []byte(paramSHA256[:]), SR, SS)
	if err != nil {
		return utils.InvokeResponse(stub, err, function, nil, false)
	}
	if !valid {
		response.StatusCode = 3
		response.StatusMsg = "signature wrong!"
		return utils.InvokeResponse(stub, err, function, response, false)
	}
	//address and pubkey relation validation
	//do payment
	bValue, err, _ := stub.GetState(payparam.SourceAddress)
	if err != nil || bValue == nil {
		return utils.InvokeResponse(stub, err, function, nil, false)
	}
	balance := bytesToInt64(bValue)
	if balance < 1 || err != nil {
		response.StatusCode = 4
		response.StatusMsg = "balance no enough!"
		return utils.InvokeResponse(stub, err, function, response, false)
	}

	NewVal := int64ToBytes(-1)
	err = stub.PutState(payparam.SourceAddress, NewVal, shim.TokenTypeValue)
	if err != nil {
		return utils.InvokeResponse(stub, err, function, nil, false)
	}
	bValue1, err, _ := stub.GetState(payparam.DestinationAddress)
	if err != nil || bValue1 == nil {
		return utils.InvokeResponse(stub, err, function, nil, false)
	}
	NewVal1 := int64ToBytes(1)
	err = stub.PutState(payparam.DestinationAddress, NewVal1, shim.TokenTypeValue)
	response.StatusCode = 0
	response.StatusMsg = "payment success"
	response.SourceAddress = payparam.SourceAddress
	response.PubKey = payparam.PubKey
	response.DestinationAddress = payparam.DestinationAddress
	response.EncryptData = payparam.EncryptData
	response.EncryptKey = payparam.EncryptKey
	return utils.InvokeResponse(stub, nil, function, response, true)
}
func SendData(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	var err error
	request := &define.PaymentParam{}
	response := &define.PaymentResponse{}
	if err = json.Unmarshal([]byte(args[1]), request); err != nil {
		return utils.InvokeResponse(stub, err, function, nil, false)
	}
	response.StatusCode = 0
	response.StatusMsg = "send success"
	response.SourceAddress = request.SourceAddress
	response.PubKey = request.PubKey
	response.DestinationAddress = request.DestinationAddress
	response.EncryptData = request.EncryptData
	response.EncryptKey = request.EncryptKey
	return utils.InvokeResponse(stub, nil, function, response, true)
}
func QueryData(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	key := args[1]
	page := define.Page{}
	result, err, _ := stub.GetState(key)
	if err != nil {
		return utils.QueryResponse(err, nil, page)
	}

	return utils.QueryResponse(nil, result, page)
}

func DslQuery(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	var err error
	request := &define.QueryRequest{}
	if err = json.Unmarshal([]byte(args[1]), request); err != nil {
		err = fmt.Errorf("DslQuery json decode args failed, err = %s", err.Error())
		return utils.QueryResponse(err, nil, request.SplitPage)
	}
	result, err := utils.GetValueByDSL(stub, request)
	if err != nil {
		return utils.QueryResponse(err, nil, request.SplitPage)
	}

	return utils.QueryResponse(nil, result, request.SplitPage)
}

func KeepaliveQuery(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	targetValue, err, _ := stub.GetState(KEEPALIVETEST)
	if err != nil {
		err = fmt.Errorf("ERROR! KeepaliveQuery get failed, err = %s", err.Error())
		return []byte("UnReached"), err
	}

	if string(targetValue) != KEEPALIVETEST {
		err = fmt.Errorf("ERROR! KeepaliveQuery get result is %s", string(targetValue))
		return []byte("UnReached"), err
	}

	return []byte("Reached"), nil
}

func UploadApplicationMaterials(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	var err error
	var materialsInfo api_def.MaterialsInfo
	var allMaterialsInfo api_def.AllMaterialsInfo

	request := &define.InvokeRequest{}
	if err = json.Unmarshal([]byte(args[1]), request); err != nil {
		return utils.InvokeResponse(stub, err, function, nil, false)
	}

	//企业资料
	orgInfo := &api_def.OrgInfo{}
	if err = json.Unmarshal([]byte(request.Value), orgInfo); err != nil {
		return utils.InvokeResponse(stub, err, function, nil, false)
	}

	//企业上传资料的次数
	org, _, _ := stub.GetState(request.Key)
	if org == nil {
		materialsInfo.UploadTimes = api_def.FIRST_TIME_UPLOAD_APPLICATIONS_INFO //申请批次
		materialsInfo.DataType = api_def.DATATYPE_APPLICATIONMATERIALS          //资料固定字段为2
	} else {
		if err = json.Unmarshal(org, &materialsInfo); err != nil {
			return utils.InvokeResponse(stub, err, function, nil, false)
		}
		materialsInfo.UploadTimes = materialsInfo.UploadTimes + 1
		materialsInfo.VerifiedInfo = nil /*企业再次上传资料清空之前审批信息*/
		materialsInfo.QueryState = ""
		materialsInfo.Suggestion = ""
	}

	materialsInfo.OrgInfo = *orgInfo
	materialsInfo.OrgID = orgInfo.OrgID
	materialsInfo.Orgname = orgInfo.EnterpriseInfo.Orgname
	materialsInfo.CreateTime = orgInfo.CreateTime

	allOrgName, err, _ := stub.GetState(api_def.ALL_MATERIALS_INFO_KEY)
	if err != nil {
		myLogger.Errorf("UploadApplicationMaterials err: %s", err.Error())
		return utils.InvokeResponse(stub, err, function, nil, false)
	}
	if allOrgName != nil {
		if err = json.Unmarshal(allOrgName, &allMaterialsInfo); err != nil {
			return utils.InvokeResponse(stub, err, function, nil, false)
		}
	} else {
		allMaterialsInfo.OrgNameList = []string{}
	}

	//如果已经存在，不需要跟新
	objectNotExist := true
	for _, v := range allMaterialsInfo.OrgNameList {
		if v == materialsInfo.Orgname {
			objectNotExist = false
		}
	}
	if objectNotExist {
		allMaterialsInfo.OrgNameList = append(allMaterialsInfo.OrgNameList, materialsInfo.Orgname)
	}

	val, _ := json.Marshal(materialsInfo)
	err = stub.PutState(request.Key, val, shim.NormalTypeValue)
	if err != nil {
		myLogger.Errorf("UploadApplicationMaterials err: %s", err.Error())
		return utils.InvokeResponse(stub, err, function, nil, false)
	}

	if objectNotExist {
		allVal, _ := json.Marshal(allMaterialsInfo)
		err = stub.PutState(api_def.ALL_MATERIALS_INFO_KEY, allVal, shim.NormalTypeValue)
		if err != nil {
			myLogger.Errorf("UploadApplicationMaterials err: %s", err.Error())
			return utils.InvokeResponse(stub, err, function, nil, false)
		}
	}

	return utils.InvokeResponse(stub, err, function, materialsInfo, true)
}

func Verifyqualification(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	var err error
	verifiedInfo := &api_def.VerifiedInfo{}
	mateinfo := &api_def.MaterialsInfo{}
	request := &define.InvokeRequest{}

	if err = json.Unmarshal([]byte(args[1]), request); err != nil {
		return utils.InvokeResponse(stub, err, function, nil, false)
	}
	if err = json.Unmarshal([]byte(request.Value), verifiedInfo); err != nil {
		return utils.InvokeResponse(stub, err, function, nil, false)
	}
	b, err, _ := stub.GetState(verifiedInfo.Auditee)
	if err != nil {
		myLogger.Errorf("Verifyqualification err: %s", err.Error())
		return utils.InvokeResponse(stub, err, function, nil, false)
	}
	if b == nil {
		return utils.InvokeResponse(stub, nil, function, nil, false)
	}

	if err = json.Unmarshal(b, mateinfo); err != nil {
		return utils.InvokeResponse(stub, err, function, nil, false)
	}
	if mateinfo.VerifiedInfo == nil {
		mateinfo.VerifiedInfo = make(map[string]api_def.VerifiedInfo)
	}
	mateinfo.VerifiedInfo[request.Key] = *verifiedInfo
	mateinfo.Suggestion = verifiedInfo.Suggestion
	count := 0
	notAgreeFlag := false
	var verifiedInfoAgree string
	for _, verify := range mateinfo.VerifiedInfo {
		if verify.Agree == api_def.MATERIAL_AGREE {
			count += 1
		} else {
			notAgreeFlag = true
			verifiedInfoAgree = verify.Agree
			break
		}
		if count >= 4 {
			notAgreeFlag = true
			verifiedInfoAgree = api_def.MATERIAL_AGREE
			break
		}
	}

	if notAgreeFlag {
		mateinfo.QueryState = verifiedInfoAgree
	} else {
		mateinfo.QueryState = fmt.Sprintf("4-%d", count)
	}
	mateinfo.VerifiedDate = verifiedInfo.VerifiedDate

	val, _ := json.Marshal(mateinfo)
	err = stub.PutState(verifiedInfo.Auditee, val, shim.NormalTypeValue)
	if err != nil {
		myLogger.Errorf("Verifyqualification err: %s", err.Error())
		return utils.InvokeResponse(stub, err, function, nil, false)
	}

	var list []string
	list = append(list, request.Value)
	return utils.InvokeResponse(stub, nil, function, list, true)

}
func int64ToBytes(i int64) []byte {
	var buf = make([]byte, 9)
	binary.BigEndian.PutUint64(buf[1:], uint64(i))
	return buf
}

func bytesToInt64(buf []byte) int64 {
	return int64(binary.BigEndian.Uint64(buf))
}
