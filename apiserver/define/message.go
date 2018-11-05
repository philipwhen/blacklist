package define

type QueryContents struct {
	Payload interface{} `json:"payload"`
}

type ParamS struct {
	Data   string `json:"Data"`
	PubKey string `json:"PubKey"`
}

type EncryptDataRequest struct {
	Method string `json:"method"`
	Param  ParamS `json:"param"`
}

type EncryptDataResponse struct {
	EncryptData string `json:"EncryptData"`
	EncryptKey  string `json:"EncryptKey"`
}

type AddrInfo struct {
	DestAddress string `json:"destAddress"`
}

type TransferRequest struct {
	Method string   `json:"method"`
	Param  AddrInfo `json:"param"`
}

type TransferResponse struct {
	ResponseCode int    `json:"ResponseCode"`
	ResponseMsg  string `json:"ResponseMsg"`
}

type AccountInformation struct {
	Address   string `json:"address"`
	Secret    string `json:"secret"`
	PublicKey string `json:"publicKey"`
}
