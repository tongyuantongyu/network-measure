package tool

import (
	lru "github.com/hashicorp/golang-lru"
	"net"
	"network-measure/tool/icmp"
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
	Probe  uint64
	Hop    uint64
	Result *icmp.Result
}

func MTR(q *MtrQ) (*MtrP, error) {
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
		Data:     make([][]MtrPEntry, q.Times),
	}

	for i := uint64(0); i < q.Times; i++ {
		r.Data[i] = make([]MtrPEntry, q.MaxHop)
	}

	resultPipe := make(chan MTRResult)
	finishPipe := make(chan struct{})
	go func() {
		end := make([]int, q.Times)
		for i := uint64(0); i < q.Times; i++ {
			end[i] = int(q.MaxHop) - 1
		}

		for result := range resultPipe {
			ip := result.Result.AddrIP.String()

			entry := &r.Data[result.Probe][result.Hop]
			entry.Code = result.Result.Code
			if entry.Code != 256 {
				entry.Address = ip
				entry.RDNS = rDNSLookup(ip)
				entry.Latency = float64(result.Result.Latency) / float64(time.Millisecond)
			}

			if entry.Code != 258 && entry.Code != 256 && int(result.Hop) < end[result.Probe] {
				end[result.Probe] = int(result.Hop)
			}
		}

		for i := uint64(0); i < q.Times; i++ {
			r.Data[i] = r.Data[i][:end[i]+1]
		}

		finishPipe <- struct{}{}
		close(finishPipe)
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
			thisCount := countTimes - 1

			//tickerInner := time.NewTicker(time.Second)
			//countHop := uint64(0)
			//hops := sync.WaitGroup{}
			//hops.Add(int(q.MaxHop))
			//for range tickerInner.C {
			//	if countHop == q.MaxHop {
			//		tickerInner.Stop()
			//		break
			//	}
			//
			//	j := int(countHop)
			//	go func() {
			//		result := <-m.Issue(addr, j + 1, timeout)
			//		resultPipe <- MTRResult{
			//			Probe:  thisCount,
			//			Hop:    uint64(j),
			//			Result: result,
			//		}
			//
			//		hops.Done()
			//	}()
			//
			//	countHop++
			//}

			hops := sync.WaitGroup{}
			hops.Add(int(q.MaxHop))
			for i := uint64(0); i < q.MaxHop; i++ {
				j := int(i)
				go func() {
					result := <-m.Issue(addr, j+1, timeout, 0)
					resultPipe <- MTRResult{
						Probe:  thisCount,
						Hop:    uint64(j),
						Result: result,
					}

					hops.Done()
				}()
			}

			hops.Wait()
			times.Done()
		}()
	}

	times.Wait()
	close(resultPipe)
	<-finishPipe
	for len(r.Data) != 0 && r.Data[len(r.Data)-1] == nil {
		r.Data = r.Data[:len(r.Data)-1]
	}
	return &r, nil
}
