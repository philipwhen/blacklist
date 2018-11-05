package define

type EnterpriseInfo struct {
	Orgname                  string    `json:"Orgname"` //企业名称，如：苏宁云商苏宁金服集团
	BusinessLicenseNo        string    `json:"BusinessLicenseNo"` //营业执照注册号，如：3011500111175682
	BusinessTerm             string	   `json:"BusinessTerm"` //营业期限，如：1990/12/20 - 2090/12/20
	BusinessLicenseAddr      string    `json:"BusinessLicenseAddr"` //营业执照所在地，如：江苏省南京市玄武区
	CommonAddr               string    `json:"CommonAddr"` //常用地址，如：徐庄软件园苏宁大道1号
	ContactName              string    `json:"ContactName"`//联系人姓名，如：张近东
	PhoneNumber              string    `json:"PhoneNumber"`//联系人手机，如：18013468789
	BusinessLicenseScancopy  string    `json:"BusinessLicenseScancopy"`//营业执照扫描件，如：
	OfficialSealcopy         string    `json:"OfficialSealcopy"`//加盖公章的副本，如：
}

type LegalPerson struct {
	Name          string    `json:"Name"` //法人名称，如：张三丰
	IdNumber      string    `json:"IdNumber"` //身份证号，如：3011500111175682
	PhoneNumber   string    `json:"PhoneNumber"` //法人练习方式，如：18013468789
	FrontPhoto    string    `json:"FrontPhoto"` //身份证正面照，如：
	BackPhoto     string    `json:"BackPhoto"` //身份证反面照，如：
}

type OrgInfo struct {
	OrgID           string    `json:"OrgID"`   //机构ID，如：222333
	EnterpriseInfo  EnterpriseInfo `json:"EnterpriseInfo"` // 企业实名信息
	LegalPerson     LegalPerson `json:"LegalPerson"` //法人实名信息
	CreateTime      uint64    `json:"CreateTime"`   //申请日期
	OrgLevel		string		`json:"OrgLevel"`	//企业级别：委员会成员，普通会员
}

type VerifiedInfo struct {
	Orgname        string    `json:"Orgname"`   //审核机构名称，如：苏宁
	Auditee        string    `json:"Auditee"`   //被审机构名称，如：江苏银行南京分行
	Agree          string    `json:"Agree"`   //审批结果，如：审核通过，驳回-企业实名，驳回-法人实名
	Suggestion     string    `json:"Suggestion"`   //审批说明，如：照片模糊，身份证验证出错
	VerifiedDate   uint64    `json:"VerifiedDate"`   //审核日期，如：2018/01/31
}

type VerifiedBase struct {
	OrgID                    string    `json:"OrgID"`   //机构ID，如：222333
	Orgname                  string    `json:"Orgname"`   //机构名称，如：江苏银行南京分行
	CreateTime               uint64    `json:"CreateTime"`   //申请日期
	VerifiedDate             uint64    `json:"VerifiedDate"`   //审核日期
	UploadTimes              int       `json:"UploadTimes"`   //申请批次，如：3
	QueryState               string    `json:"QueryState"`   //申批状态，如：4-4，驳回-企业实名，驳回-法人实名
	Suggestion               string    `json:"Suggestion"`   //审批说明，如：照片模糊，身份证验证出错
	OperationState           string    `json:"OperationState"`   //运营状态，如：正常，屏蔽
	Statements               string    `json:"Statements"`   //状态说明，如：数据质量差
}

//上链信息
type MaterialsInfo struct {
	OrgInfo         OrgInfo                   `json:"OrgInfo"` //企业资料基本信息
    OrgID           string    `json:"OrgID"`   //机构ID，如：222333
    Orgname         string    `json:"Orgname"`   //机构名称，如：江苏银行南京分行
    CreateTime      uint64    `json:"CreateTime"`   //申请日期
    VerifiedDate    uint64    `json:"VerifiedDate"`   //审核日期
    UploadTimes     int                       `json:"UploadTimes"`   //申请批次，如：3
	VerifiedInfo    map[string]VerifiedInfo   `json:"VerifiedInfo"`   //审核结果 
	QueryState      string                    `json:"QueryState"`   //申批状态，如：4-4，驳回-企业实名，驳回-法人实名 
	Suggestion      string                    `json:"Suggestion"`   //审批说明，如：照片模糊，身份证验证出错
	DataType        uint64                    `json:"DataType"`     // 资料固定字段为2
}

type UploadMaterialsResponse struct {
    ResponseCode    string    `json:"ResponseCode"` // 返回码
    ResponseMsg     string    `json:"ResponseMsg"`  //返回信息
}

type QueryMaterialsRequest struct {
    Orgname        string    `json:"Orgname"` //名称
}

type QueryMaterialsResponse struct {
    ResponseCode    string    `json:"ResponseCode"` // 返回码
    ResponseMsg     string    `json:"ResponseMsg"`  //返回信息
    OrgInfo         OrgInfo   `json:"OrgInfo"`     //企业信息
}

type QueryOrganizationsInfoRequest struct {
    Orgname                  string    `json:"Orgname"`   //查询机构名称，如：江苏银行南京分行
    OrgID                    string    `json:"OrgID"`   //被查询机构ID，如：222333
    Auditee                  string    `json:"Auditee"`   //被查询机构
    CreateTimeFrom           uint64    `json:"CreateTimeFrom"`   //申请时间，起始日期，如：1517821540秒
    CreateTimeTo             uint64    `json:"CreateTimeTo"`   //申请时间，结束日期，如：1566666666秒
    UploadTimes              int       `json:"UploadTimes"`   //申请批次，如：3
    AgreeOrNot               bool      `json:"AgreeOrNot"`   //查询机构已审批和未审批，如：
}

type QueryOrganizationsInfoResponse struct {
    ResponseCode    string              `json:"ResponseCode"` // 返回码
    ResponseMsg     string              `json:"ResponseMsg"`  //返回信息
    VerifiedAgree    []VerifiedBase     `json:"VerifiedAgree"`  //本机构已审批的企业资料信息
    VerifiedNotAgree []VerifiedBase     `json:"VerifiedNotAgree"`  //本机构未审批的企业资料信息
    NotVerifiledCnt uint64              `json:"NotVerifiledCnt"` //查询机构查询到的待审批机构个数
}

type AllMaterialsInfo struct {
	OrgNameList 	[]string `json:"OrgNameList"`   //企业名称列表
}
