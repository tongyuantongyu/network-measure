package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"network-measure/tool"
	"os"

	"golang.org/x/sync/semaphore"
)

var dataStorage [56]byte

type measureResult struct {
	addr     string
	received int
	latency  float64
	score    float64
}

const concurrency = 16

func main() {
	_, _ = rand.Read(dataStorage[:])
	sema := semaphore.NewWeighted(concurrency)
	reporter := make(chan measureResult)
	f, err := os.OpenFile("result.txt", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0755)
	if err != nil {
		log.Fatalf("can't open file: %s\n", err)
	}

	measure := func(addr string) {
		defer sema.Release(1)

		tcp, err := tool.TCPing(&tool.TCPingQ{
			Address:  addr,
			Family:   0,
			Port:     443,
			Wait:     1000,
			Interval: 1000,
			Times:    4,
		})

		if err != nil {
			log.Printf("failed tcping %s: %s\n", addr, err)
		}

		result := measureResult{
			addr: addr,
		}
		for _, record := range tcp.Data {
			if record.Success {
				result.received++
				result.latency += record.Latency
				result.score += 1000 - record.Latency
			}
		}

		if result.received == 0 {
			result.latency = 1000
		} else {
			result.latency /= float64(result.received)
		}

		result.score /= 4000 / 100 // rescale from 4000 to 100
		reporter <- result
	}

	go func() {
		for result := range reporter {
			log.Printf("%s score %.2f, %.2fms of %d success\n", result.addr, result.score, result.latency, result.received)
			_, err := fmt.Fprintf(f, "%s %f %f %d\n", result.addr, result.score, result.latency, result.received)
			if err != nil {
				log.Fatalf("Failed write record: %s\n", err)
			}
		}

		_ = f.Close()
	}()

	for i := 0; i < 0xff; i++ {
		addr := fmt.Sprintf("0.0.0.%d", i)
		if i%0x100 == 0 {
			log.Printf("Now at %s\n", addr)
		}
		_ = sema.Acquire(context.Background(), 1)
		go measure(addr)
	}

	_ = sema.Acquire(context.Background(), concurrency)
	close(reporter)
}
