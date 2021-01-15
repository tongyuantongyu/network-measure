package main

import (
	"fmt"
	lru "github.com/hashicorp/golang-lru"
	"net"
	"network-measure/icmp"
	"sync"
	"time"
)

var cache *lru.TwoQueueCache
var once sync.Once

func getRDNSCache() *lru.TwoQueueCache {
	once.Do(func() {
		cache, _ = lru.New2Q(8192)
	})
	return cache
}

func rDNSLookup(ip string) string {
	c := getRDNSCache()
	if entry, ok := c.Get(ip); ok {
		return entry.(string)
	} else {
		rdns, err := net.LookupAddr(ip)
		if err != nil {
			return ""
		}
		record := ""
		if len(rdns) != 0 {
			selected := rdns[0]
			if selected[len(selected)-1] == '.' {
				selected = selected[:len(selected)-1]
			}
			record = selected
		}
		c.Add(ip, record)
		return record
	}
}

type MTRResult struct {
	Hop    uint64
	Result *icmp.Result
}

func mtr(q *MtrQ) (*MtrP, error) {
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
	} else if q.Interval < 10 {
		q.Interval = 10
	}

	if q.MaxHop > 100 {
		q.MaxHop = 100
	}

	network, err := getNetwork("ip", q.Family)
	if err != nil {
		return nil, err
	}

	addr, err := net.ResolveIPAddr(network, q.Address)
	if err != nil {
		return nil, err
	}

	r := MtrP{
		Resolved: addr.String(),
		Data:     make([][]MtrPEntry, q.MaxHop),
	}

	resultPipe := make(chan MTRResult)
	go func() {
		for result := range resultPipe {
			if result.Result.Code == 256 {
				continue
			}

			fmt.Printf("{%d}, {%+v}\n", result.Hop, *result.Result)

			ip := result.Result.AddrIP.String()
			r.Data[result.Hop] = append(r.Data[result.Hop], MtrPEntry{
				Address: ip,
				RDNS:    rDNSLookup(ip),
				Code:    result.Result.Code,
				Latency: float64(result.Result.Latency) / float64(time.Millisecond),
			})
		}
	}()

	m := icmp.GetICMPManager()
	times := sync.WaitGroup{}
	times.Add(int(q.Times))
	ticker := time.NewTicker(time.Duration(q.Interval) * time.Millisecond)
	timeout := time.Duration(q.Wait) * time.Millisecond
	countTimes := uint64(0)
	for range ticker.C {
		if countTimes == q.Times {
			ticker.Stop()
			break
		}

		countTimes++
		go func() {
			for i := uint64(0); i < q.MaxHop; i++ {
				result := <-m.Issue(addr, int(i), timeout)
				resultPipe <- MTRResult{
					Hop:    i,
					Result: result,
				}

				if result.Code != 258 && result.Code != 256 {
					break
				}
			}

			times.Done()
		}()
	}

	times.Wait()
	for r.Data[len(r.Data)-1] == nil {
		r.Data = r.Data[:len(r.Data)-1]
	}
	return &r, nil
}
