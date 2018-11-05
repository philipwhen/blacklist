package router

import (
	"sync"

	"github.com/peersafe/poc_blacklist/apiserver/handler"

	"github.com/gin-gonic/gin"
)

// Router 全局路由
var router *gin.Engine
var onceCreateRouter sync.Once

func GetRouter() *gin.Engine {
	onceCreateRouter.Do(func() {
		router = createRouter()
	})

	return router
}

func createRouter() *gin.Engine {
	router := gin.Default()
	// 版本控制
	// v1 := Router.Group("/v1")
	// {
	// factor
	bill := router.Group("/blacklist")
	{
		//Blacklist Infomation
		bill.POST("/uploadblacklist", handler.Uploadblacklist)
		bill.POST("/queryblacklistunpay", handler.QueryBlackListUnpay)
		bill.POST("/queryblacklisttotal", handler.QueryBlackListTotal)
		bill.POST("/senddata", handler.SendData)
		//bill.POST("/createAddress", handler.CreateAddress)
		bill.POST("/", handler.ProcessRequest)
		//Corporate Information
		bill.POST("/uploadapplicationmaterials", handler.UploadApplicationMaterials) //提交资料
		bill.POST("/queryapplicationmaterials", handler.QueryApplicationMaterials)   //查询资料
		bill.POST("/verifyqualification", handler.Verifyqualification)               //审核资料
		bill.POST("/queryorganizationsinfo", handler.QueryOrganizationsInfo)         //查询审核信息

		//Probe Information
		bill.HEAD("/keepaliveQuery", handler.KeepaliveQuery)
	}
	//upload schema json file
	return router
}
