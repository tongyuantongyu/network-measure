package tool

import (
	"context"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
)

func TCPing(q *TCPingQ) (*TCPingP, error) {
	if q.Times > 100 {
		q.Times = 100
	}

	if q.Wait < 10 {
		q.Wait = 10
	} else if q.Wait > 10000 {
		q.Wait = 10000
	}

	if q.Interval > 10000 {
		q.Interval = 10000
	}

	network, err := getNetwork("tcp", q.Family)
	if err != nil {
		return nil, err
	}

	var host string
	if q.Family != 4 && strings.Contains(q.Address, ":") && q.Address[0] != '[' {
		host = fmt.Sprintf("[%s]:%d", q.Address, q.Port)
	} else {
		host = fmt.Sprintf("%s:%d", q.Address, q.Port)
	}

	addr, err := net.ResolveTCPAddr(network, host)
	if err != nil {
		return nil, err
	}

	r := TCPingP{
		Resolved: addr.IP.String(),
		Data:     make([]TCPingPEntry, 0, q.Times),
	}

	var now time.Time
	var ctx context.Context
	var cancel context.CancelFunc
	var timer *time.Timer
	wait := time.Duration(q.Wait) * time.Millisecond
	d := net.Dialer{
		Control: func(string, string, syscall.RawConn) error {
			now = time.Now()
			timer = time.AfterFunc(wait, func() {
				cancel()
			})
			return nil
		},
	}

	if q.Family != 0 {
		d.FallbackDelay = -time.Millisecond
	}

	for i := uint64(0); i < q.Times; i++ {
		ctx, cancel = context.WithCancel(context.Background())
		conn, err := d.DialContext(ctx, network, host)
		if err != nil {
			r.Data = append(r.Data, TCPingPEntry{
				Success: false,
				Latency: float64(time.Since(now)) / float64(time.Millisecond),
			})
		} else {
			r.Data = append(r.Data, TCPingPEntry{
				Success: true,
				Latency: float64(time.Since(now)) / float64(time.Millisecond),
			})
			_ = conn.Close()
		}
		timer.Stop()
		cancel()
		time.Sleep(time.Duration(q.Interval) * time.Millisecond)
	}

	return &r, nil
}
