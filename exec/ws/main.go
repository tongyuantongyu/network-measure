package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/gorilla/websocket"
	json "github.com/json-iterator/go"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"network-measure/tool"
	"network-measure/tool/icmp"
	"time"
)

var config Config

const (
	cmdResolve = iota
	cmdPing
	cmdTCPing
	cmdMTR
	cmdSpeed
)

var cmdMap = map[uint32]func([]byte) []byte{
	cmdResolve: handleResolve,
	cmdPing:    handlePing,
	cmdTCPing:  handleTCPing,
	cmdMTR:     handleMTR,
	cmdSpeed:   handleSpeed,
}

type Response struct {
	Type    uint32
	Payload []byte
}

func jsonResult(id uint64, r interface{}, e error) (b []byte) {
	if e != nil {
		b, _ = json.Marshal(gin.H{
			"id":   id,
			"ok":   false,
			"info": e.Error(),
		})
	} else {
		b, _ = json.Marshal(gin.H{
			"id":     id,
			"ok":     true,
			"result": r,
		})
	}

	return
}

func handleResolve(body []byte) (r []byte) {
	var q struct {
		ID uint64        `json:"id"`
		Q  tool.ResolveQ `json:"request"`
	}
	if err := binding.JSON.BindBody(body, &q); err != nil {
		r = jsonResult(q.ID, nil, err)
		return
	}

	rs, err := tool.Resolve(&q.Q)
	r = jsonResult(q.ID, rs, err)

	if err == nil {
		log.Printf("Done resolving address of `%s`.\n", q.Q.Address)
	}

	return
}

func handlePing(body []byte) (r []byte) {
	var q struct {
		ID uint64     `json:"id"`
		Q  tool.PingQ `json:"request"`
	}

	if err := binding.JSON.BindBody(body, &q); err != nil {
		r = jsonResult(q.ID, nil, err)
		return
	}

	rs, err := tool.Ping(&q.Q)
	r = jsonResult(q.ID, rs, err)

	if err == nil {
		log.Printf("Done ping `%s` for %d times.\n", q.Q.Address, q.Q.Times)
	}

	return
}

func handleTCPing(body []byte) (r []byte) {
	var q struct {
		ID uint64       `json:"id"`
		Q  tool.TCPingQ `json:"request"`
	}

	if err := binding.JSON.BindBody(body, &q); err != nil {
		r = jsonResult(q.ID, nil, err)
		return
	}

	rs, err := tool.TCPing(&q.Q)
	r = jsonResult(q.ID, rs, err)

	if err == nil {
		log.Printf("Done tcping `%s` for %d times.\n", q.Q.Address, q.Q.Times)
	}

	return
}

func handleMTR(body []byte) (r []byte) {
	var q struct {
		ID uint64    `json:"id"`
		Q  tool.MtrQ `json:"request"`
	}

	if err := binding.JSON.BindBody(body, &q); err != nil {
		r = jsonResult(q.ID, nil, err)
		return
	}

	rs, err := tool.MTR(&q.Q)
	r = jsonResult(q.ID, rs, err)

	if err == nil {
		log.Printf("Done mtr `%s` for %d times.\n", q.Q.Address, q.Q.Times)
	}

	return
}

func handleSpeed(body []byte) (r []byte) {
	var q struct {
		ID uint64      `json:"id"`
		Q  tool.SpeedQ `json:"request"`
	}

	if err := binding.JSON.BindBody(body, &q); err != nil {
		r = jsonResult(q.ID, nil, err)
		return
	}

	rs, err := tool.Speed(&q.Q)
	r = jsonResult(q.ID, rs, err)

	if err == nil {
		log.Printf("Done speedtest `%s` for %d milliseconds.\n", q.Q.URL, q.Q.Span)
	}

	return
}

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
}

func main() {
	var dialer = websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		ReadBufferSize:   1048576,
		WriteBufferSize:  1048576,
	}

	h := hmac.New(sha256.New, []byte(config.Conn.Key))
	identifier := fmt.Sprintf("%s.%x.%x", config.Conn.Name, time.Now().Unix(), rand.Uint64())
	h.Write([]byte(identifier))
	header := http.Header{}
	header.Set("X-Identifier", identifier)
	header.Set("X-Signature", hex.EncodeToString(h.Sum(nil)))

	retryCount := uint32(0)

	for {
		conn, _, err := dialer.Dial(config.Conn.Remote, header)
		stopper := make(chan struct{})
		pChan := make(chan Response, 16)
		if err != nil {
			if retryCount < config.Conn.Retry {
				retryCount++
				log.Printf("Can't establish connection to server %s: %s\n", config.Conn.Remote, err)
				goto CleanUp
			} else {
				log.Fatalf("Can't establish connection to server %s: %s\n", config.Conn.Remote, err)
			}
		}

		go func() {
			tick := time.NewTicker(time.Second * 10)

			select {
			case <-tick.C:
				_ = conn.WriteMessage(websocket.PingMessage, []byte("keep-alive"))
			case <-stopper:
				stopper <- struct{}{}
				return
			}
		}()

		go func() {
			for {
				select {
				case p := <-pChan:
					msg := make([]byte, len(p.Payload)+8)
					binary.BigEndian.PutUint32(msg[:4], p.Type)
					binary.BigEndian.PutUint32(msg[4:8], uint32(len(p.Payload)))
					copy(msg[8:], p.Payload)
					if err := conn.WriteMessage(websocket.BinaryMessage, msg); err != nil {
						log.Printf("Failed writing response: %s\n", err)
					}
				case <-stopper:
					stopper <- struct{}{}
					return
				}
			}
		}()

		conn.SetPongHandler(func(string) error {
			retryCount = 0
			return nil
		})

	NextMsg:
		for {
			t, r, err := conn.NextReader()
			if err != nil {
				log.Printf("Connection broken: %s\n", err)
				goto CleanUp
			}

			if t == websocket.CloseMessage {
				payload, err := ioutil.ReadAll(r)
				if err != nil {
					log.Printf("Connection closed. Can't read reason: %s\n", err)
					stopper <- struct{}{}
					goto CleanUp
				}

				log.Printf("Connection closed: %s\n", string(websocket.FormatCloseMessage(t, string(payload))))
			}

			headBuffer := make([]byte, 4)
			if n, err := r.Read(headBuffer); err != nil || n != 4 {
				log.Printf("Bad type marker: %x (len %d)\n", headBuffer, n)
				continue
			}
			qType := binary.BigEndian.Uint32(headBuffer)

			if n, err := r.Read(headBuffer); err != nil || n != 4 {
				log.Printf("Bad length marker: %x (len %d)\n", headBuffer, n)
				continue
			}
			length := binary.BigEndian.Uint32(headBuffer)
			if length > 1048576 {
				log.Printf("Invalid length: %d\n", length)
				continue
			}

			reqBuffer := make([]byte, length)

			for read := 0; read < int(length); {
				n, err := r.Read(reqBuffer)
				read += n
				if err != nil {
					log.Printf("Failed reading request (%d read, %d expect): %s\n", read, length, err)
					continue NextMsg
				}
			}

			if handler, ok := cmdMap[qType]; ok {
				go func() {
					p := handler(reqBuffer)
					select {
					case <-stopper:
						stopper <- struct{}{}
					case pChan <- Response{
						Type:    qType,
						Payload: p,
					}:
					}
				}()
			} else {
				log.Printf("Bad command type: %d\n", qType)
			}
		}

	CleanUp:
		pChan = nil
		stopper <- struct{}{}
		_ = conn.Close()
		icmp.FinishICMPManager()

		time.Sleep(time.Second * 10)
	}

}
