package define

type CreatTime struct {
	Year   string `json:"Year"`   //年
	Month  string `json:"Month"`  //月
	Day    string `json:"Day"`    //日
	Hour   string `json:"Hour"`   //小时
	Minute string `json:"Minute"` //分
	Second string `json:"Second"` //秒
}

type BlackListCommon struct {
	UserId        string `json:"UserID"`        //用户ID（已脱敏）
	UserName      string `json:"UserName"`      //用户姓名（已脱敏）
	ListUniqueKey string `json:"ListUniqueKey"` //黑名单唯一编号
	ListType      string `json:"ListType"`      //黑名单类型
	PaymentAddr   string `json:"PaymentAddr"`   //收款地址
	PaymentPubKey string `json:"PaymentPubKey"` //收款公钥
	ListStatus    uint64 `json:"ListStatus"`    //名单状态
	FabricTxId    string `json:"FabricTxId"`    //Fabric交易ID
}

type BlackListInfo struct {
	CommData    BlackListCommon `json:"CommData"`    //黑名单基础信息
	CreatTime   CreatTime       `json:"CreatTime"`   //创建时间
	SpecialData string          `json:"SpecialData"` //黑名单详细信息（链上存储加密信息）
	EncryKey    string          `json:"EncryKey"`    //黑名单详细信息（链上存储加密信息）
}

type BlackListResponse struct {
	ResponseCode string   `json:"ResponseCode"` // 返回码
	ResponseMsg  string   `json:"ResponseMsg"`  //返回信息
	FabricID     []string `json:"FabricID"`     // fabric交易ID
}
type PaymentRequest struct {
	Method string       `json:"method"`
	Param  PaymentParam `json:"param"`
}
type PaymentParam struct {
	SourceSecret string `json:"sourceSecret"`
	Source       string `json:"source"`
	PubKey       string `json:"PubKey"`
	Destination  string `json:"Destination"`
	EncryptData  string `json:"EncryptData"`
	EncryptKey   string `json:"EncryptKey"`
}
type PaymentResponse struct {
	ResponseCode string `json:"ResponseCode"` // 返回码
	ResponseMsg  string `json:"ResponseMsg"`  //返回信息
	ResultData   string `json:"resultData"`
}
type BalanceQueryRequest struct {
	Method string            `json:"method"`
	Param  BalanceQueryParam `json:"param"`
}
type BalanceQueryParam struct {
	Addresses []string `json:"addresses"`
}
type BalanceQueryResponse struct {
	ResponseCode string                   `json:"ResponseCode"` // 返回码
	ResponseMsg  string                   `json:"ResponseMsg"`  //返回信息
	ResultData   map[string][]BalanceData `json:"resultData"`
}
type BalanceData struct {
	Currency string `json:"currency"`
	Value    string `json:"value"`
}
type BlackListQueryUnpayRequest struct {
	UserID   string `json:"UserID"`   // 用户ID（已脱敏）
	UserName string `json:"UserName"` // 用户姓名（已脱敏）
}

type BlackListQueryUnpayResponse struct {
	ResponseCode string          `json:"ResponseCode"` //返回码
	ResponseMsg  string          `json:"ResponseMsg"`  //返回信息
	Payload      []BlackListInfo `json:"Payload"`      //消息数组
}
type AccountCreateResponse struct {
	ResponseCode string             `json:"ResponseCode"` // 返回码
	ResponseMsg  string             `json:"ResponseMsg"`  //返回信息
	ResultData   AccountInformation `json:"resultData"`   //返回信息
}
type BlackTypeCnt struct {
	ListType string `json:"ListType"` //黑名单类型
	ListCnt  uint64 `json:"ListCnt"`  //黑名单类型
}

type BlackListTotalCnt struct {
	Total         uint64         `json:"Total"`         //所有黑名单总数
	TypeCount     []BlackTypeCnt `json:"TypeCount"`     //各类型总数
	CurMonthCount uint64         `json:"CurMonthCount"` //当月总数
}

type BlackListQueryTotalCntResponse struct {
	ResponseCode string            `json:"ResponseCode"` //返回码
	ResponseMsg  string            `json:"ResponseMsg"`  //返回信息
	Payload      BlackListTotalCnt `json:"Payload"`      //消息数组
}

type BlackListCntInfo struct {
	BlackListCnt        map[string]int `json:"BlackListCnt"`        // 黑名单统计字段，如："TotalCnt"、"1~7"、"2018-3"
	AddListUniqueKey    []string       `json:"AddListUniqueKey"`    // 新增黑名单的唯一编号列表
	UpdateListUniqueKey []string       `json:"UpdateListUniqueKey"` // 更新黑名单的唯一编号列表
	DeleteListUniqueKey []string       `json:"DeleteListUniqueKey"` // 删除黑名单的唯一编号列表
	OperationTime       string         `json:"OperationTime"`       // 操作时间
}
