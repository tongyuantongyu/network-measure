package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"github.com/BurntSushi/toml"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/jellydator/ttlcache/v2"
	"io/ioutil"
	"log"
	"net/http"
	"network-measure/bind"
	"network-measure/tool"
	"os"
	"strconv"
	"time"
)

var config Config
var nonceMap = ttlcache.NewCache()

var (
	fullVersion string
	buildDate   string
)

func init() {
	log.Printf("network-measure HTTP %s, built at %s\n", fullVersion, buildDate)
	config.SetDefault()
	if c, err := os.ReadFile("./config.toml"); err == nil {
		if err = toml.Unmarshal(c, &config); err != nil {
			log.Printf("Failed loading config: %s, use default settings.\n", err)
			config.SetDefault()
		} else {
			log.Println("Config loaded.")
		}
	} else {
		log.Println("No config found. use default settings.")
	}

	if err := bind.Parse(config.Network.Bind); err != nil {
		log.Fatalf("Failed parse binding: %s\n", err)
	}

	_ = nonceMap.SetTTL(60 * time.Second)
}

func jsonResult(c *gin.Context, r interface{}, e error) {
	if e != nil {
		c.JSON(http.StatusNotAcceptable, gin.H{
			"ok":   false,
			"info": e.Error(),
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"ok":     true,
			"result": r,
		})
	}
}

func verifyStamp(c *gin.Context, timeStamp, nonce uint64) bool {
	if time.Since(time.Unix(int64(timeStamp), 0)) > 60*time.Second {
		c.String(http.StatusUnauthorized, "Stamp timeout")
		c.Abort()
		return false
	}

	nonceString := strconv.FormatUint(nonce, 16)
	if _, err := nonceMap.Get(nonceString); err != ttlcache.ErrNotFound {
		c.String(http.StatusUnauthorized, "Nonce already used")
		c.Abort()
		return false
	}

	_ = nonceMap.Set(nonceString, struct{}{})
	return true
}

func handleResolve(c *gin.Context) {
	var q tool.ResolveQ
	if err := binding.JSON.BindBody(c.Keys["body"].([]byte), &q); err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, err).SetType(gin.ErrorTypeBind)
		return
	}

	if config.Auth.UseAuth && !verifyStamp(c, q.TimeStamp, q.Nonce) {
		return
	}

	r, err := tool.Resolve(&q)
	jsonResult(c, r, err)

	if err == nil {
		log.Printf("Done resolving address of `%s`.\n", q.Address)
	} else {
		log.Printf("Failed resolving address of `%s`: %s\n", q.Address, err)
	}
}

func handlePing(c *gin.Context) {
	var q tool.PingQ
	if err := binding.JSON.BindBody(c.Keys["body"].([]byte), &q); err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, err).SetType(gin.ErrorTypeBind)
		return
	}

	if config.Auth.UseAuth && !verifyStamp(c, q.TimeStamp, q.Nonce) {
		return
	}

	r, err := tool.Ping(&q)
	jsonResult(c, r, err)

	if err == nil {
		log.Printf("Done ping `%s` for %d times.\n", q.Address, q.Times)
	} else {
		log.Printf("Failed ping `%s`: %s\n", q.Address, err)
	}
}

func handleTCPing(c *gin.Context) {
	var q tool.TCPingQ
	if err := binding.JSON.BindBody(c.Keys["body"].([]byte), &q); err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, err).SetType(gin.ErrorTypeBind)
		return
	}

	r, err := tool.TCPing(&q)
	jsonResult(c, r, err)

	if err == nil {
		log.Printf("Done tcping `%s` for %d times.\n", q.Address, q.Times)
	} else {
		log.Printf("Failed tcping `%s`: %s\n", q.Address, err)
	}
}

func handleMTR(c *gin.Context) {
	var q tool.MtrQ
	if err := binding.JSON.BindBody(c.Keys["body"].([]byte), &q); err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, err).SetType(gin.ErrorTypeBind)
		return
	}

	if config.Auth.UseAuth && !verifyStamp(c, q.TimeStamp, q.Nonce) {
		return
	}

	r, err := tool.MTR(&q)
	jsonResult(c, r, err)

	if err == nil {
		log.Printf("Done mtr `%s` for %d times.\n", q.Address, q.Times)
	} else {
		log.Printf("Failed mtr `%s`: %s\n", q.Address, err)
	}
}

func handleSpeed(c *gin.Context) {
	var q tool.SpeedQ
	if err := binding.JSON.BindBody(c.Keys["body"].([]byte), &q); err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, err).SetType(gin.ErrorTypeBind)
		return
	}

	if config.Auth.UseAuth && !verifyStamp(c, q.TimeStamp, q.Nonce) {
		return
	}

	r, err := tool.Speed(&q, !config.API.SpeedUnsafe)
	jsonResult(c, r, err)

	if err == nil {
		log.Printf("Done speedtest `%s` for %d milliseconds.\n", q.URL, q.Span)
	} else {
		log.Printf("Failed speedtest `%s`: %s\n", q.URL, err)
	}
}

func handleTLS(c *gin.Context) {
	var q tool.TlsQ
	if err := binding.JSON.BindBody(c.Keys["body"].([]byte), &q); err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, err).SetType(gin.ErrorTypeBind)
		return
	}

	if config.Auth.UseAuth && !verifyStamp(c, q.TimeStamp, q.Nonce) {
		return
	}

	r, err := tool.TLS(&q)
	jsonResult(c, r, err)

	if err == nil {
		log.Printf("Done tls handshake to `%s`.\n", q.Address)
	} else {
		log.Printf("Failed tls handshake to `%s`: %s\n", q.Address, err)
	}
}

func verify(c *gin.Context) {
	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	c.Set("body", body)

	if !config.Auth.UseAuth {
		c.Next()
		return
	}

	h := hmac.New(sha256.New, []byte(config.Auth.Key))

	sign := c.GetHeader("X-Signature")
	hexSign, err := hex.DecodeString(sign)
	if sign == "" || err != nil {
		c.String(http.StatusUnauthorized, "Missing signature")
		c.Abort()
		return
	}

	h.Write(body)

	if !hmac.Equal(hexSign, h.Sum(nil)) {
		c.String(http.StatusUnauthorized, "Invalid signature")
		c.Abort()
		return
	}

	c.Next()
}

func limit(enable bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if enable {
			c.Next()
		} else {
			c.String(http.StatusForbidden, "API not enabled")
			c.Abort()
			return
		}
	}
}

//func _(c *gin.Context) {
//	fmt.Printf("[DBG] %v | %15s | %-7s  %#v\n",
//		time.Now().Format("2006/01/02 - 15:04:05"),
//		c.ClientIP(),
//		c.Request.Method,
//		c.Request.URL.Path,
//	)
//}

func main() {
	router := gin.Default()
	a := router.Group("/api", verify)
	{
		a.POST("/resolve", limit(config.API.Resolve), handleResolve)
		a.POST("/ping", limit(config.API.Ping), handlePing)
		a.POST("/tcping", limit(config.API.TCPing), handleTCPing)
		a.POST("/mtr", limit(config.API.MTR), handleMTR)
		a.POST("/speed", limit(config.API.Speed), handleSpeed)
		a.POST("/tls", limit(config.API.TLS), handleTLS)
	}
	router.HandleMethodNotAllowed = true

	if config.Site.Cert != "" && config.Site.Key != "" {
		_ = router.RunTLS(config.Site.Listen, config.Site.Cert, config.Site.Key)
	} else {
		_ = router.Run(config.Site.Listen)
	}
}
