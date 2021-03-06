package tool

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
)

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

type NetworkFixedDialer struct {
	D              *net.Dialer
	Network        string
	RemoteReporter func(string)
}

func (d *NetworkFixedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if len(d.Network) == 0 {
		return d.D.DialContext(ctx, network, address)
	}
	conn, err := d.D.DialContext(ctx, d.Network, address)
	if err != nil {
		return nil, errors.New("connection failed")
	} else {
		addr := conn.RemoteAddr().(*net.TCPAddr)
		if isLocal(addr) {
			_ = conn.Close()
			return nil, errors.New("connection failed")
		} else {
			d.RemoteReporter(addr.IP.String())
			return conn, nil
		}
	}
}

func request(url string, ctx context.Context) (req *http.Request, err error) {
	req, err = http.NewRequestWithContext(ctx, "GET", url, nil)
	return
}

func Speed(q *SpeedQ) (*SpeedP, error) {
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

	network, err := getNetwork("tcp", q.Family)
	if err != nil {
		return nil, err
	}

	r := SpeedP{}

	var fallbackDelay time.Duration
	if q.Family != 0 {
		fallbackDelay = -time.Millisecond
	} else {
		fallbackDelay = 0
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: (&NetworkFixedDialer{
				D: &net.Dialer{
					Timeout:       30 * time.Second,
					KeepAlive:     30 * time.Second,
					FallbackDelay: fallbackDelay,
				},
				Network: network,
				RemoteReporter: func(s string) {
					r.Resolved = s
				},
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	buffer := make([]byte, 131072)

	ctx, cancel := context.WithCancel(context.Background())
	req, err := request(q.URL, ctx)
	if err != nil {
		cancel()
		return nil, errors.New("bad url")
	}

	now := time.Now()

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

	now = time.Now()
	for {
		n, err := resp.Body.Read(buffer)
		elapsed := time.Since(now)
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
