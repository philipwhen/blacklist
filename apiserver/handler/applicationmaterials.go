package handler

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/peersafe/poc_blacklist/apiserver/define"
	"github.com/peersafe/poc_blacklist/apiserver/sdk"
	"github.com/peersafe/poc_blacklist/apiserver/utils"

	"github.com/gin-gonic/gin"
)

func IfMatrialeRange(dataTime uint64, fromTime uint64, toTime uint64) bool {
    if toTime == 0 {
        if dataTime >= fromTime {
            return true
        }
    } else {
        if dataTime >= fromTime && dataTime <= toTime {
            return true
        }
    }
    return false
}

// 申请加入联盟的机构上传联盟会员资质申请资料到区块链上
func UploadApplicationMaterials(c *gin.Context) {
	utils.Log.Debug("upload application materials .....")

	var orgInfo define.OrgInfo
	var response define.UploadMaterialsResponse
	var err error

	status := http.StatusOK

	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		utils.Log.Errorf("UploadApplicationMaterials read body : %s", err.Error())
		status = http.StatusNoContent
        response.ResponseCode = strconv.Itoa(status)
        response.ResponseMsg = err.Error()
		utils.Response(response, c, http.StatusNoContent)
		return
	}

	utils.Log.Debugf("UploadApplicationMaterials header : %v", c.Request.Header)
	utils.Log.Debugf("UploadApplicationMaterials body : %s", string(body))

	if err = json.Unmarshal(body, &orgInfo); err != nil {
		utils.Log.Errorf("UploadApplicationMaterials Unmarshal : %s", err.Error())
		status = http.StatusBadRequest
        response.ResponseCode = strconv.Itoa(status)
        response.ResponseMsg = err.Error()
		utils.Response(response, c, http.StatusBadRequest)
		return
	}

	txId, nonce, err := sdk.Handler.GetTxId()
	if err != nil {
		utils.Log.Errorf("UploadApplicationMaterials GetTxId : %s", err.Error())
		status = http.StatusServiceUnavailable
		response.ResponseCode = strconv.Itoa(status)
		response.ResponseMsg = err.Error()
		utils.Response(response, c, status)
		return
	}

	var invokeRequest define.InvokeRequest
	val, _ := json.Marshal(orgInfo)
	invokeRequest.Value = string(val)
	invokeRequest.Key = fmt.Sprintf("%s", orgInfo.EnterpriseInfo.Orgname)
	b, _ := json.Marshal(invokeRequest)

	// invoke
	_, err = sdk.Handler.Invoke(txId, nonce, "", define.UPLOAD_APPLICATION_MATERIALS, nil, b)
	if err != nil {
		utils.Log.Errorf("SaveData Invoke : %s", err.Error())
		status = http.StatusServiceUnavailable
		response.ResponseCode = strconv.Itoa(status)
		response.ResponseMsg = err.Error()
		utils.Response(response, c, status)
		return
	}
	response.ResponseCode = strconv.Itoa(status)
	response.ResponseMsg = "submit success!"
	utils.Response(response, c, status)
}


func QueryApplicationMaterials(c *gin.Context) {
    utils.Log.Debug("QueryApplicationMaterials .....")

    var request define.QueryMaterialsRequest
    var response define.QueryMaterialsResponse
    var appMaterials define.MaterialsInfo
    var err error

    // query
    status := http.StatusOK

    utils.Log.Debugf("query header : %v", c.Request.Header)

    body, err := ioutil.ReadAll(c.Request.Body)
    if err != nil {
        utils.Log.Errorf("QueryBlackListPay read body : %s", err.Error())
        status = http.StatusNoContent
        response.ResponseCode = strconv.Itoa(status)
        response.ResponseMsg = err.Error()
        utils.Response(response, c, http.StatusNoContent)
        return
    }
    utils.Log.Debugf("query body : %s", string(body))

    if err = json.Unmarshal(body, &request); err != nil {
        utils.Log.Errorf("QueryBlackListPay Unmarshal : %s", err.Error())
        status = http.StatusBadRequest
        response.ResponseCode = strconv.Itoa(status)
        response.ResponseMsg = err.Error()
        utils.Response(response, c, http.StatusBadRequest)
        return
    }

    b := request.Orgname
    responseData, _, err := sdk.Handler.QueryData("", define.QUERY_DATA, nil, b)
    if err != nil {
        utils.Log.Errorf("QueryBlackListPay Query : %s", err.Error())
        status = http.StatusServiceUnavailable
        response.ResponseCode = strconv.Itoa(status)
        response.ResponseMsg = err.Error()
        utils.Response(response, c, http.StatusBadRequest)
        return
    }
    if responseData.Payload == nil {
        status = http.StatusNotFound
        response.ResponseCode = strconv.Itoa(status)
        response.ResponseMsg = "The specified block was not found"
        utils.Response(response, c, http.StatusNotFound)
        return
    }

    if err = json.Unmarshal(responseData.Payload.([]byte), &appMaterials); err != nil {
        utils.Log.Errorf("QueryBlackListPay Unmarshal : %s", err.Error())
        status = http.StatusBadRequest
        response.ResponseCode = strconv.Itoa(status)
        response.ResponseMsg = err.Error()
        utils.Response(response, c, http.StatusBadRequest)
        return
    }
    
    
    response.ResponseCode = strconv.Itoa(status)
    response.ResponseMsg = "query success!"
    response.OrgInfo = appMaterials.OrgInfo
    utils.Response(response, c, status)
}

func Verifyqualification(c *gin.Context) {
	utils.Log.Debug("Verify qualification .....")

	var response define.UploadMaterialsResponse
	var verinfo define.VerifiedInfo
	var err error

	status := http.StatusOK

	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		utils.Log.Errorf("verifyqualification read body : %s", err.Error())
		status = http.StatusNoContent
		response.ResponseCode = strconv.Itoa(status)
		response.ResponseMsg = err.Error()
		utils.Response(response, c, http.StatusNoContent)
		return
	}

	utils.Log.Debugf("verifyqualification header : %v", c.Request.Header)
	utils.Log.Debugf("verifyqualification body : %s", string(body))

	if err = json.Unmarshal(body, &verinfo); err != nil {
		utils.Log.Errorf("verifyqualification Unmarshal : %s", err.Error())
		status = http.StatusBadRequest
		response.ResponseCode = strconv.Itoa(status)
		response.ResponseMsg = err.Error()
		utils.Response(response, c, http.StatusBadRequest)
		return
	}

	txId, nonce, err := sdk.Handler.GetTxId()
	if err != nil {
		utils.Log.Errorf("UploadApplicationMaterials GetTxId : %s", err.Error())
		status = http.StatusServiceUnavailable
		response.ResponseCode = strconv.Itoa(status)
		response.ResponseMsg = err.Error()
		utils.Response(response, c, status)
		return
	}

	val, _ := json.Marshal(verinfo)
	var invokeRequest define.InvokeRequest
	invokeRequest.Value = string(val)
	invokeRequest.Key = fmt.Sprintf("%s", verinfo.Orgname)
	b, _ := json.Marshal(invokeRequest)

	// invoke
	_, err = sdk.Handler.Invoke(txId, nonce, "", define.VERIFY_QUALIFICATION, nil, b)
	if err != nil {
		utils.Log.Errorf("SaveData Invoke : %s", err.Error())
		status = http.StatusServiceUnavailable
		response.ResponseCode = strconv.Itoa(status)
		response.ResponseMsg = err.Error()
		utils.Response(response, c, status)
		return
	}
	response.ResponseCode = strconv.Itoa(status)
	response.ResponseMsg = "verify success!"
	utils.Response(response, c, status)
}

func QueryOrganizationsInfo(c *gin.Context) {
    utils.Log.Debug("QueryOrganizationsInfo .....")

    var qInReq define.QueryOrganizationsInfoRequest
    var allMaterialsInfo define.AllMaterialsInfo
    var response define.QueryOrganizationsInfoResponse
    var err error

    status := http.StatusOK    
    body, err := ioutil.ReadAll(c.Request.Body)
    if err != nil {
        utils.Log.Errorf("verifyqualification read body : %s", err.Error())
        status = http.StatusNoContent
        response.ResponseCode = strconv.Itoa(status)
        response.ResponseMsg = err.Error()
        utils.Response(response, c, http.StatusNoContent)
        return
    }

    utils.Log.Debugf("verifyqualification header : %v", c.Request.Header)
    utils.Log.Debugf("verifyqualification body : %s", string(body))

    if err = json.Unmarshal(body, &qInReq); err != nil {
        utils.Log.Errorf("verifyqualification Unmarshal : %s", err.Error())
        status = http.StatusBadRequest
        response.ResponseCode = strconv.Itoa(status)
        response.ResponseMsg = err.Error()
        utils.Response(response, c, http.StatusBadRequest)
        return
    }

    responseData, _, err := sdk.Handler.QueryData("", define.QUERY_DATA, nil, define.ALL_MATERIALS_INFO_KEY)
    if err != nil {
        utils.Log.Errorf("QueryOrganizationsInfo Query : %s", err.Error())
        status = http.StatusServiceUnavailable
        response.ResponseCode = strconv.Itoa(status)
        response.ResponseMsg = err.Error()
        utils.Response(response, c, http.StatusBadRequest)
        return
    }
    if responseData.Payload == nil {
        status = http.StatusNotFound
        response.ResponseCode = strconv.Itoa(status)
        response.ResponseMsg = "The specified block was not found"
        utils.Response(response, c, http.StatusNotFound)
        return
    }

    if err = json.Unmarshal(responseData.Payload.([]byte), &allMaterialsInfo); err != nil {
        utils.Log.Errorf("QueryOrganizationsInfo Unmarshal : %s", err.Error())
        status = http.StatusBadRequest
        response.ResponseCode = strconv.Itoa(status)
        response.ResponseMsg = err.Error()
        utils.Response(response, c, http.StatusBadRequest)
        return
    }

    NotVerifiedCount := 0
    for _, OrgName := range allMaterialsInfo.OrgNameList {
        responseData, _, err := sdk.Handler.QueryData("", define.QUERY_DATA, nil, OrgName)
        if err != nil {
            utils.Log.Errorf("QueryOrganizationsInfo Query : %s", err.Error())
            status = http.StatusServiceUnavailable
            response.ResponseCode = strconv.Itoa(status)
            response.ResponseMsg = err.Error()
            utils.Response(response, c, http.StatusBadRequest)
            return
        }
        if responseData.Payload == nil {
            status = http.StatusNotFound
            response.ResponseCode = strconv.Itoa(status)
            response.ResponseMsg = "The specified block was not found"
            utils.Response(response, c, http.StatusNotFound)
            return
        }

        appMaterials := &define.MaterialsInfo{}
        if err = json.Unmarshal(responseData.Payload.([]byte), appMaterials); err != nil {
            utils.Log.Errorf("QueryOrganizationsInfo Unmarshal : %s", err.Error())
            status = http.StatusBadRequest
            response.ResponseCode = strconv.Itoa(status)
            response.ResponseMsg = err.Error()
            utils.Response(response, c, http.StatusBadRequest)
            return
        }
        vb := utils.FormatMaterialsVerify(*appMaterials)
        /*find not verified and verified*/
        verifiedFlag := false
        if appMaterials.VerifiedInfo != nil {
            if _, ok := appMaterials.VerifiedInfo[qInReq.Orgname] ; ok {
                verifiedFlag = true
            }
        }
        if verifiedFlag {
            response.VerifiedAgree = append(response.VerifiedAgree, vb)
        } else {
            NotVerifiedCount += 1
            response.VerifiedNotAgree = append(response.VerifiedNotAgree, vb)
        }
    }
    response.NotVerifiledCnt = uint64(NotVerifiedCount)
    response.ResponseCode = strconv.Itoa(status)
    response.ResponseMsg = "query success!"
    utils.Response(response, c, status)
}

func QueryOrganizationsInfo_bak(c *gin.Context) {
    utils.Log.Debug("QueryOrganizationsInfo .....")

    var qInReq define.QueryOrganizationsInfoRequest
    var response define.QueryOrganizationsInfoResponse
    var err error

    status := http.StatusOK    
    body, err := ioutil.ReadAll(c.Request.Body)
    if err != nil {
        utils.Log.Errorf("verifyqualification read body : %s", err.Error())
        status = http.StatusNoContent
        response.ResponseCode = strconv.Itoa(status)
        response.ResponseMsg = err.Error()
        utils.Response(response, c, http.StatusNoContent)
        return
    }

    utils.Log.Debugf("verifyqualification header : %v", c.Request.Header)
    utils.Log.Debugf("verifyqualification body : %s", string(body))

    if err = json.Unmarshal(body, &qInReq); err != nil {
        utils.Log.Errorf("verifyqualification Unmarshal : %s", err.Error())
        status = http.StatusBadRequest
        response.ResponseCode = strconv.Itoa(status)
        response.ResponseMsg = err.Error()
        utils.Response(response, c, http.StatusBadRequest)
        return
    }

    var strOrgId string    //被查询机构ID
    var strOrgName string   //被查询机构NAME
    var strUploadTimes string  //上传次数

    if qInReq.OrgID != "" {
        strOrgId = fmt.Sprintf(",\"OrgID\":\"%s\"", qInReq.OrgID)
    }

    if qInReq.Auditee != "" {
        strOrgName = fmt.Sprintf(",\"Orgname\":\"%s\"", qInReq.Auditee)
    }

    if qInReq.UploadTimes != 0 {
        strUploadTimes = fmt.Sprintf(",\"UploadTimes\": %d", qInReq.UploadTimes)
    }

    // query
    var request define.QueryRequest
    dslStr := fmt.Sprintf("{\"selector\":{\"DataType\": %d", define.DATATYPE_APPLICATIONMATERIALS)
    dslStr += strOrgId + strOrgName + strUploadTimes + "}}"
    request.DslSyntax = dslStr
    b, _ := json.Marshal(request)
    responseData, _, err := sdk.Handler.QueryDslData("", define.DSL_QUERY, nil, string(b))
    if err != nil {
        utils.Log.Errorf("DslQuery Query : %s", err.Error())
        status = http.StatusServiceUnavailable
        response.ResponseCode = strconv.Itoa(status)
        response.ResponseMsg = err.Error()
        utils.Response(response, c, http.StatusBadRequest)
        return
    }

    NotVerifiedCount := 0
    mtInfos, ok := responseData.Payload.([]string)
    if ok {
        for _, jsonVal := range mtInfos {
            var mInfo define.MaterialsInfo
            err = json.Unmarshal([]byte(jsonVal), &mInfo)
            if err == nil {
                vb := utils.FormatMaterialsVerify(mInfo)
                if IfMatrialeRange(mInfo.CreateTime, qInReq.CreateTimeFrom,qInReq.CreateTimeTo) {
                   /*find not verified and verified*/
                   verifiedFlag := false
                   if mInfo.VerifiedInfo != nil {
                      if _, ok := mInfo.VerifiedInfo[qInReq.Orgname] ; ok {
                          verifiedFlag = true
                      }
                   }

                   if verifiedFlag {
                      response.VerifiedAgree = append(response.VerifiedAgree, vb)
                   } else {
                       NotVerifiedCount += 1
                       response.VerifiedNotAgree = append(response.VerifiedNotAgree, vb)
                   }
                }
                
            } else {
                utils.Log.Errorf("Unmarshal err: %s", err.Error())
            }
        }
        response.NotVerifiledCnt = uint64(NotVerifiedCount)
    } 

    response.ResponseCode = strconv.Itoa(status)
    utils.Response(response, c, status)
}
