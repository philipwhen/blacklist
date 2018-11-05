package define

const (
	UPLOAD_BLACKLIST              = "Upload_blacklist"
	QUERY_DATA                    = "QueryData"
	SAVE_DATA                     = "SaveData"
	DSL_QUERY                     = "DslQuery"
	KEEPALIVE_QUERY               = "KeepaliveQuery"
	UPLOAD_APPLICATION_MATERIALS  = "UploadApplicationMaterials"
	VERIFY_QUALIFICATION          = "Verifyqualification"
	GET_BALANCE                   = "GetBalance"
	PAYMENT                       = "Payment"
	SENDDATA                      = "Senddata"
	DATATYPE_BLACKLIST            = 1
	DATATYPE_APPLICATIONMATERIALS = 2

	FIRST_TIME_UPLOAD_APPLICATIONS_INFO = 1
	CRYPTO_PATH                         = "./crypto/"

	MATERIAL_AGREE      = "审核通过"
	MATERIAL_NOTAGREE_E = "驳回-企业实名"
	MATERIAL_NOTAGREE_P = "驳回-法人实名"

	ALL_MATERIALS_INFO_KEY = "AllMaterialsInfoKey"

	CHAINSQL_ENCRYPT         = "ENCRYPT"
	CHAINSQL_TRANSFERACCOUNT = "Transferaccount"

	PEER_FAIL_CODE     = 601
	ORDER_FAIL_CODE    = 602
	BLACK_TRANSFER_ERR = 603

	BLACKLIST_TOTAL_COUNT = "TotalCnt" // 黑名单总数
)
