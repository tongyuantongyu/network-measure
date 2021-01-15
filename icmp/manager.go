package icmp

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// An Result represents an Result (EchoReply, TimeExceed or SetTimeout
// without response)
type Result struct {
	// response source ip
	AddrIP net.IP `json:"addr"`
	// time passed from request time
	Latency time.Duration `json:"latency"`
	// ICMP code
	Code int `json:"code"`
}

// Manager represents a manager to send and recv packet of a specific network
type Manager interface {
	// Issue submit a probe to the manager and return a channel. A Result will
	// be sent through the channel and the channel will be closed then.
	Issue(net.Addr, int, time.Duration) chan *Result
	// Finish stops the manager from continue serving the requests.
	Finish()
}

type Request interface {
	SetTimeout(time.Duration)
	Passed(time.Time) bool
	Deliver(Response) bool
}

type Response interface {
	GetIdentifier() (int, net.IP)
	GetInformation() (net.IP, time.Time, int)
}

// Concurrent map implementation by orcaman(https://github.com/orcaman)
// Modification to use int as key by penhauer-xiao(https://github.com/penhauer-xiao)

// Copyright (c) 2014 streamrail
// Use of this source code is governed by MIT license that
// can be found in the concurrent-map.LICENSE file.

type ConMapRequest struct {
	Shards  int
	HashMap ConcurrentMapRequest
}

// A "thread" safe map of type int:Anything.
// To avoid lock bottlenecks this map is dived to several (Shards) map shards.
type ConcurrentMapRequest []*ConcurrentMapSharedRequest

// A "thread" safe int to anything map.
type ConcurrentMapSharedRequest struct {
	items        map[int]Request
	sync.RWMutex // Read Write mutex, guards access to internal map.
}

// Creates a new concurrent map.
func NewCMap(shards int) *ConMapRequest {
	m := &ConMapRequest{Shards: shards, HashMap: make(ConcurrentMapRequest, shards)}
	for i := 0; i < shards; i++ {
		m.HashMap[i] = &ConcurrentMapSharedRequest{items: make(map[int]Request)}
	}
	return m
}

// Returns shard under given key
func (m *ConMapRequest) GetShard(key int) *ConcurrentMapSharedRequest {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(key))
	return m.HashMap[fnv32(b)%uint32(m.Shards)]
}

// Retrieves an element from map under given key.
func (m *ConMapRequest) Get(key int) (Request, bool) {
	// Get shard
	shard := m.GetShard(key)
	shard.RLock()
	// Get item from shard.
	val, ok := shard.items[key]
	shard.RUnlock()
	return val, ok
}

// Sets the given value under the specified key.
func (m *ConMapRequest) Set(key int, value Request, timeout time.Duration) {
	// Get map shard.
	shard := m.GetShard(key)
	// Here may consume some time, so move issue time calc inside
	shard.Lock()
	value.SetTimeout(timeout)
	shard.items[key] = value
	shard.Unlock()
}

// Returns the number of elements within the map.
func (m *ConMapRequest) Count() int {
	count := 0
	for i := 0; i < m.Shards; i++ {
		shard := m.HashMap[i]
		shard.RLock()
		count += len(shard.items)
		shard.RUnlock()
	}
	return count
}

// Used by the Iter & IterBuffered functions to wrap two variables together over a channel,
type Tuple struct {
	Key int
	Val Request
}

// Returns a buffered iterator which could be used in a for range loop.
func (m *ConMapRequest) IterBuffered() <-chan Tuple {
	chans := snapshot(m)
	total := 0
	for _, c := range chans {
		total += cap(c)
	}
	ch := make(chan Tuple, total)
	go fanIn(chans, ch)
	return ch
}

// Returns a array of channels that contains elements in each shard,
// which likely takes a snapshot of `m`.
// It returns once the size of each buffered channel is determined,
// before all the channels are populated using goroutines.
func snapshot(m *ConMapRequest) (chans []chan Tuple) {
	chans = make([]chan Tuple, m.Shards)
	wg := sync.WaitGroup{}
	wg.Add(m.Shards)
	// Foreach shard.
	for index, shard := range m.HashMap {
		go func(index int, shard *ConcurrentMapSharedRequest) {
			// Foreach key, value pair.
			shard.RLock()
			chans[index] = make(chan Tuple, len(shard.items))
			wg.Done()
			for key, val := range shard.items {
				chans[index] <- Tuple{key, val}
			}
			shard.RUnlock()
			close(chans[index])
		}(index, shard)
	}
	wg.Wait()
	return chans
}

// fanIn reads elements from channels `chans` into channel `out`
func fanIn(chans []chan Tuple, out chan Tuple) {
	wg := sync.WaitGroup{}
	wg.Add(len(chans))
	for _, ch := range chans {
		go func(ch chan Tuple) {
			for t := range ch {
				out <- t
			}
			wg.Done()
		}(ch)
	}
	wg.Wait()
	close(out)
}

// Removes an element from the map.
func (m *ConMapRequest) Remove(key int) {
	// Try to get shard.
	shard := m.GetShard(key)
	shard.Lock()
	delete(shard.items, key)
	shard.Unlock()
}

// Removes an element from the map and returns it
func (m *ConMapRequest) Pop(key int) (v Request, exists bool) {
	// Try to get shard.
	shard := m.GetShard(key)
	shard.Lock()
	v, exists = shard.items[key]
	delete(shard.items, key)
	shard.Unlock()
	return v, exists
}

func fnv32(key []byte) uint32 {
	hash := uint32(2166136261)
	const prime32 = uint32(16777619)
	for i := 0; i < len(key); i++ {
		hash *= prime32
		hash ^= uint32(key[i])
	}
	return hash
}
