package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"github.com/BurntSushi/toml"
	"github.com/ReneKroon/ttlcache/v2"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"
)

var config Config
var nonceMap = ttlcache.NewCache()

func init() {
	config.SetDefault()
	if c, err := ioutil.ReadFile("./config.toml"); err == nil {
		if err = toml.Unmarshal(c, &config); err != nil {
			log.Printf("Failed loading config: %s, use default settings.\n", err)
			config.SetDefault()
		} else {
			log.Println("Config loaded.")
		}
	} else {
		log.Println("No config found. use default settings.")
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
	var q ResolveQ
	if err := binding.JSON.BindBody(c.Keys["body"].([]byte), &q); err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, err).SetType(gin.ErrorTypeBind)
		return
	}

	if config.Auth.UseAuth && !verifyStamp(c, q.TimeStamp, q.Nonce) {
		return
	}

	r, err := resolve(&q)
	jsonResult(c, r, err)

	if err == nil {
		log.Printf("Done resolving address of `%s`.\n", q.Address)
	}
}

func handlePing(c *gin.Context) {
	var q PingQ
	if err := binding.JSON.BindBody(c.Keys["body"].([]byte), &q); err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, err).SetType(gin.ErrorTypeBind)
		return
	}

	if config.Auth.UseAuth && !verifyStamp(c, q.TimeStamp, q.Nonce) {
		return
	}

	r, err := ping(&q)
	jsonResult(c, r, err)

	if err == nil {
		log.Printf("Done ping `%s` for %d times.\n", q.Address, q.Times)
	}
}

func handleTCPing(c *gin.Context) {
	var q TCPingQ
	if err := binding.JSON.BindBody(c.Keys["body"].([]byte), &q); err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, err).SetType(gin.ErrorTypeBind)
		return
	}

	r, err := tcping(&q)
	jsonResult(c, r, err)

	if err == nil {
		log.Printf("Done tcping `%s` for %d times.\n", q.Address, q.Times)
	}
}

func handleMTR(c *gin.Context) {
	var q MtrQ
	if err := binding.JSON.BindBody(c.Keys["body"].([]byte), &q); err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, err).SetType(gin.ErrorTypeBind)
		return
	}

	if config.Auth.UseAuth && !verifyStamp(c, q.TimeStamp, q.Nonce) {
		return
	}

	r, err := mtr(&q)
	jsonResult(c, r, err)

	if err == nil {
		log.Printf("Done mtr `%s` for %d times.\n", q.Address, q.Times)
	}
}

func handleSpeed(c *gin.Context) {
	var q SpeedQ
	if err := binding.JSON.BindBody(c.Keys["body"].([]byte), &q); err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, err).SetType(gin.ErrorTypeBind)
		return
	}

	if config.Auth.UseAuth && !verifyStamp(c, q.TimeStamp, q.Nonce) {
		return
	}

	r, err := speed(&q)
	jsonResult(c, r, err)

	if err == nil {
		log.Printf("Done speedtest `%s` for %d milliseconds.\n", q.URL, q.Span)
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

func main() {
	router := gin.Default()
	a := router.Group("/api", verify)
	{
		a.POST("/resolve", limit(config.API.Resolve), handleResolve)
		a.POST("/ping", limit(config.API.Ping), handlePing)
		a.POST("/tcping", limit(config.API.TCPing), handleTCPing)
		a.POST("/mtr", limit(config.API.MTR), handleMTR)
		a.POST("/speed", limit(config.API.Speed), handleSpeed)
	}
	router.HandleMethodNotAllowed = true

	if config.Site.Cert != "" && config.Site.Key != "" {
		_ = router.RunTLS(config.Site.Listen, config.Site.Cert, config.Site.Key)
	} else {
		_ = router.Run(config.Site.Listen)
	}
}
