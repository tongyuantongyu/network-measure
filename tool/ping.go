package tool

import (
	"math/rand"
	"net"
	"network-measure/tool/icmp"
	"time"
)

func Ping(q *PingQ) (*PingP, error) {
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

	network, err := getNetwork("ip", q.Family, "")
	if err != nil {
		return nil, err
	}

	addr, err := net.ResolveIPAddr(network, q.Address)
	if err != nil {
		return nil, err
	}

	r := PingP{
		Resolved: addr.String(),
		Data:     make([]PingPEntry, 0, q.Times),
	}

	m := icmp.GetICMPManager()
	id := getICMPID()
	for i := uint64(0); i < q.Times; i++ {
		payload := icmp.ICMPPayload{ID: id, Seq: int(i), Data: make([]byte, 56)}
		rand.Read(payload.Data)
		result := <-m.Issue(addr, 100, time.Duration(q.Wait)*time.Millisecond, payload)
		r.Data = append(r.Data, PingPEntry{
			IP:      result.AddrIP.String(),
			Code:    result.Code,
			Latency: float64(result.Latency) / float64(time.Millisecond),
		})
		time.Sleep(time.Duration(q.Interval) * time.Millisecond)
	}

	return &r, nil
}
