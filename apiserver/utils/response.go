package utils

import (
	"encoding/json"

	"github.com/gin-gonic/gin"
)

// Response http response
func Response(response interface{}, c *gin.Context, status int) {
	b, _ := json.Marshal(response)
	c.Writer.Header().Set("version", c.Request.Header.Get("version"))
	//c.Writer.Header().Set("content-Type", c.Request.Header.Get("content-Type"))
	c.Writer.Header().Set("content-Type", "application/json; charset=UTF-8")
	c.Writer.Header().Set("trackId", c.Request.Header.Get("trackId"))
	c.Writer.Header().Set("language", c.Request.Header.Get("language"))
	c.Writer.Header().Set("www-Authenticate", c.Request.Header.Get("www-Authenticate"))
	c.Writer.Header().Set("signatureAlgorithm", c.Request.Header.Get("signatureAlgorithm"))

	c.Writer.WriteHeader(status)

	c.Writer.Write(b)
}
