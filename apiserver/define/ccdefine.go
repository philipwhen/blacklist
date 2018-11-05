package define

type InvokeRequest struct {
	Key   string `json:"key"`   //存储数据的key
	Value string `json:"value"` //存储数据的value
}

type InvokeResponse struct {
	ResStatus ResponseStatus `json:"responseStatus"`
	Payload   interface{}    `json:"payload"`
}

type QueryRequest struct {
	DslSyntax string `json:"dslSyntax"` //couchDB 查询语法
	SplitPage Page   `json:"page"`      //分页
}

type QueryResponse struct {
	ResponseStatus ResponseStatus `json:"responseStatus"`
	Page           Page           `json:"page"`
	Payload        interface{}    `json:"payload"`
}

type ResponseStatus struct {
	StatusCode int    `json:"statusCode"` //错误码0:成功1:失败
	StatusMsg  string `json:"statusMsg"`  //错误信息
}

type Page struct {
	CurrentPage  uint `json:"currentPage"`  //当前页码
	PageSize     uint `json:"pageSize"`     //每个页面显示个数
	TotalRecords uint `json:"totalRecords"` //总记录数
}

type BlacklistKeyData struct {
	BlkLists         map[string]BlackListInfo `json:"BlkLists"`
	BlackListCntInfo BlackListCntInfo         `json:"BlackListCntInfo"` // 黑名单统计字段信息
	DataType         uint64                   `json:"DataType"`         // 黑名单固定字段为1
}
type BalanceKeyData struct {
	ResultData []BalanceDataCC `json:"resultData"`
}
type BalanceDataCC struct {
	Address string `json:"address"` //积分地址
	Value   string `json:"value"`   //积分余额
}

type PaymentParamCC struct {
	SourceAddress      string `json:"source"`
	PubKey             string `json:"PubKey"`
	DestinationAddress string `json:"Destination"`
	EncryptData        string `json:"EncrytData"`
	EncryptKey         string `json:"EncrytKey"`
}
type PaymentRequestCC struct {
	Param     string `json:"param"`
	Signature string `json:"signature"`
}
type PaymentResponseCC struct {
	StatusCode         int    `json:"statusCode"` //错误码0:成功1:失败
	StatusMsg          string `json:"statusMsg"`  //错误信息
	SourceAddress      string `json:"source"`
	PubKey             string `json:"PubKey"`
	DestinationAddress string `json:"Destination"`
	EncryptData        string `json:"EncrytData"`
	EncryptKey         string `json:"EncrytKey"`
}
