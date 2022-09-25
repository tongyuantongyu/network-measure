package tool

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"network-measure/bind"
	"strings"
	"time"
)

var speedUA = "network-measure Speedtest Client v1"

func isLocal(addr *net.TCPAddr) bool {
	if !addr.IP.IsGlobalUnicast() {
		return true
	}

	if ip4 := addr.IP.To4(); ip4 != nil {
		if ip4[0] == 10 {
			return true
		}
		if ip4[0] == 172 && ip4[1]&0xf == 16 {
			return true
		}
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		return false
	} else {
		ip6 := addr.IP.To16()
		return ip6[0] == 0xfd && ip6[1] == 0x00
	}
}

type PatchedDialer struct {
	D       *net.Dialer
	Network string
	safe    bool
}

func (d *PatchedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.Network == "" {
		return d.D.DialContext(ctx, network, address)
	}
	conn, err := d.D.DialContext(ctx, d.Network, address)
	if err != nil {
		return nil, errors.New("connection failed")
	}
	addr := conn.RemoteAddr().(*net.TCPAddr)
	if d.safe && isLocal(addr) {
		_ = conn.Close()
		return nil, errors.New("connection failed")
	}
	return conn, nil
}

func request(url string, ctx context.Context) (req *http.Request, err error) {
	req, err = http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", speedUA)
	return
}

func Speed(q *SpeedQ, safe bool) (*SpeedP, error) {
	if q.Wait < 10 {
		q.Wait = 10
	} else if q.Wait > 30000 {
		q.Wait = 30000
	}

	if q.Span > 240000 {
		q.Span = 240000
	}

	if q.Interval != 0 && q.Interval < 100 {
		q.Interval = 100
	}

	if !strings.HasPrefix(q.URL, "http://") &&
		!strings.HasPrefix(q.URL, "https://") {
		q.URL = "http://" + q.URL
	}

	r := SpeedP{}
	var now time.Time

	buffer := make([]byte, 131072)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			switch addr := info.Conn.RemoteAddr().(type) {
			case *net.TCPAddr:
				r.Resolved = addr.IP.String()
			case *net.UDPAddr:
				r.Resolved = addr.IP.String()
			}
		},
		GotFirstResponseByte: func() {
			if r.Trace.FirstByte == 0 {
				r.Trace.FirstByte = float64(time.Since(now)) / float64(time.Millisecond)
			}
		},
		ConnectDone: func(network, addr string, err error) {
			if err == nil && r.Trace.Conn == 0 {
				r.Trace.Conn = float64(time.Since(now)) / float64(time.Millisecond)
			}
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if err == nil && r.Trace.TLS == 0 {
				r.Trace.TLS = float64(time.Since(now)) / float64(time.Millisecond)
			}
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil && r.Trace.Sent == 0 {
				r.Trace.Sent = float64(time.Since(now)) / float64(time.Millisecond)
			}
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			if info.Err == nil && r.Trace.Sent == 0 {
				r.Trace.DNS = float64(time.Since(now)) / float64(time.Millisecond)
			}
		},
	})
	req, err := request(q.URL, ctx)
	if err != nil {
		return nil, errors.New("bad url")
	}

	network, err := getNetwork("tcp", q.Family, req.Host)
	if err != nil {
		return nil, err
	}

	var fallbackDelay time.Duration
	var laddr net.Addr
	if network != "tcp" {
		fallbackDelay = -time.Millisecond
	} else {
		if bind.Set() {
			return nil, errors.New("this instance explicitly binds to specific ip, but is unable to determine socket family to use")
		}
		if network == "tcp4" {
			laddr = &net.TCPAddr{IP: bind.LAddr4().IP}
		} else if network == "tcp6" {
			laddr = &net.TCPAddr{IP: bind.LAddr6().IP, Zone: bind.LAddr6().Zone}
		}
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: (&PatchedDialer{
				D: &net.Dialer{
					Timeout:       30 * time.Second,
					KeepAlive:     30 * time.Second,
					FallbackDelay: fallbackDelay,
					LocalAddr:     laddr,
				},
				Network: network,
				safe:    safe,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	now = time.Now()
	canceller := make(chan struct{})

	go func() {
		timer := time.NewTimer(time.Duration(q.Wait) * time.Millisecond)
		select {
		case <-timer.C:
			cancel()
		case <-canceller:
			timer.Stop()
			return
		}
	}()

	resp, err := client.Do(req)

	if err != nil {
		return nil, errors.New("connection failed")
	}

	defer resp.Body.Close()
	canceller <- struct{}{}
	r.Latency = float64(time.Since(now)) / float64(time.Millisecond)
	timer := time.NewTimer(time.Duration(q.Span) * time.Millisecond)
	go func() {
		_, ok := <-timer.C
		if ok {
			cancel()
		}
	}()

	acc := uint64(0)
	last := time.Duration(0)
	interval := time.Duration(q.Interval) * time.Millisecond
	pushReceive := func(elapsed time.Duration, n uint64) {
		acc += n
		if elapsed-last > interval {
			r.Data = append(r.Data, SpeedPEntry{
				TimePoint: float64(elapsed) / float64(time.Millisecond),
				Received:  acc,
			})
			last = elapsed
			acc = 0
		}
	}

	rcvStart := time.Now()
	for {
		n, err := resp.Body.Read(buffer)
		elapsed := time.Since(rcvStart)
		if err != nil {
			r.Elapsed = float64(elapsed) / float64(time.Millisecond)
			if !strings.Contains(err.Error(), "context canceled") {
				timer.Stop()
			}
			break
		}

		r.Received += uint64(n)
		if q.Interval > 0 {
			pushReceive(elapsed, uint64(n))
		}
	}

	return &r, nil
}
