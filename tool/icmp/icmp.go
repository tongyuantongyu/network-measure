package icmp

import (
	"bytes"
	"context"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"log"
	"math/rand"
	"net"
	"network-measure/bind"
	"network-measure/tool/fasttime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

var Debug bool

// An ICMPRequest represents an ICMPRequest issued by ping or trace for listener
// to get corresponding Result

type ICMPPayload struct {
	ID   int
	Seq  int
	Data []byte
}

type ICMPRequest struct {
	ICMPPayload
	// target ip of the request, extend identify field
	TargetIP net.IP
	// return timeout Result if Deadline passed.
	Deadline fasttime.Time
	// request issue time
	IssueTime fasttime.Time
	// channel to return result
	delivery chan *Result
}

func (r *ICMPRequest) SetTimeout(duration time.Duration) {
	r.IssueTime = fasttime.Now()
	r.Deadline = r.IssueTime.Add(duration)
}

func (r *ICMPRequest) Passed(time fasttime.Time) bool {
	return r.Deadline.Before(time)
}

func (r *ICMPRequest) Deliver(response Response) bool {
	if r.delivery == nil {
		return false
	}

	if response == nil {
		r.delivery <- &Result{
			Code: 256,
		}
		r.delivery = nil
		return true
	}
	id, targetIP := response.GetIdentifier()
	if r.ID == id && targetIP.Equal(r.TargetIP) {
		if data, ok := response.GetVerifier().([]byte); ok {
			l := len(data)
			if l > len(r.Data) {
				l = len(r.Data)
			}
			if !bytes.Equal(r.Data[:l], data[:l]) {
				log.Printf("Message body mismatch from %s, id %d, seq %d. Collision or message tampered?\n",
					targetIP.String(), id, r.Seq)
				return false
			}
			if Debug && len(data) != len(r.Data) {
				log.Printf("[DEBUG] Data payload length mismatch: sent %d bytes, got %d bytes.\n", len(r.Data), len(data))
			}
		}

		addrIP, received, code := response.GetInformation()
		if Debug {
			if code == 257 {
				log.Printf("[DEBUG] In %9.4fms, Echo->%39s@%d, 257<-@%d\n", float64(received.Since(r.IssueTime))/float64(time.Millisecond),
					r.TargetIP, r.IssueTime, received)
			} else {
				log.Printf("[DEBUG] In %9.4fms, Echo->%39s@%d, %3d<-%s@%d\n", float64(received.Since(r.IssueTime))/float64(time.Millisecond),
					r.TargetIP, r.IssueTime, code, addrIP, received)
			}

		}
		if r.Passed(received) {
			r.delivery <- &Result{
				Code: 256,
			}
			log.Printf("Late arrived response from %s: overdue %s.\n", addrIP, received.Sub(r.Deadline))
		} else {
			r.delivery <- &Result{
				AddrIP:  addrIP,
				Latency: received.Sub(r.IssueTime),
				Code:    code,
			}
		}
		r.delivery = nil
		return true
	}
	return false
}

// An ICMPResponse represents an ICMPResponse (EchoReply, TimeExceed or DstUnreachable)
type ICMPResponse struct {
	// response source ip
	AddrIP net.IP
	// target ip of the request
	TargetIP net.IP
	// payload
	ICMPPayload
	// time passed from request time
	Received fasttime.Time
	// Code of ICMP destination unreachable message response
	Code int
}

func (i *ICMPResponse) GetIdentifier() (int, net.IP) {
	return i.ID, i.TargetIP
}

func (i *ICMPResponse) GetInformation() (net.IP, fasttime.Time, int) {
	return i.AddrIP, i.Received, i.Code
}

func (i *ICMPResponse) GetVerifier() any {
	return i.Data
}

// A RawResponse represents an ICMPResponse (TimeExceed or DstUnreachable) of none-ICMP request
type RawResponse struct {
	// response source ip
	AddrIP net.IP
	// time passed from request time
	Received fasttime.Time
	// target ip of the request
	TargetIP net.IP
	// Code of ICMP destination unreachable message response
	Code int
	// Protocol is the protocol field recovered from IP Header
	Protocol int
	// Fragment is the first 8 bytes fragment of the request
	Fragment []byte
}

// An ICMPManager listens on ICMP and ICMPv6 packets and identify them to
// response of corresponding request.
type ICMPManager struct {
	// queue stores the pending requests seq and their response channel.
	// once it gots ICMPResponse it will send them back to the request owner.
	// we don't use native map to ensure thread safety
	//queue map[int]*ICMPRequest
	queue *ConMapRequest
	// extListener stores external ICMP TimeExceed/DstUnreachable listeners
	// which send other Protocol message(e.g. TCP, UDP) but expect ICMP reply
	// messages.
	extListener map[int]chan *RawResponse
	// counter will fill the sequence field of the request (use low 16bits)
	// to identify packet. it will be increased for each call and can hold at
	// most 65536 concurrent pending requests.
	counter uint32
	// context to send the manager stop message
	ctx context.Context
	// function to call to stop the manager
	cancel context.CancelFunc
	// icmp packet conn and mutex of related network
	pConn4 *icmp.PacketConn
	lc4    sync.Mutex
	pConn6 *icmp.PacketConn
	lc6    sync.Mutex

	sent     uint32
	received uint32
}

var manager *ICMPManager
var once sync.Once

type icmpReceived struct {
	addr net.Addr
	data []byte
	curr fasttime.Time
}

const mtu = 1500

type recvBuffer [mtu]byte

var bufPool = sync.Pool{
	New: func() any {
		return new(recvBuffer)
	},
}

func receiver(ctx context.Context, conn *icmp.PacketConn, data chan *icmpReceived) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		bufArray := bufPool.Get().(*recvBuffer)
		buf := bufArray[:mtu]
		n, sAddr, connErr := conn.ReadFrom(buf)
		curr := fasttime.Now()
		if connErr != nil || sAddr == nil || n == 0 {
			bufPool.Put(bufArray)
			continue
		}

		if Debug {
			atomic.AddUint32(&manager.received, 1)
		}

		select {
		case data <- &icmpReceived{
			addr: sAddr,
			data: buf[:n],
			curr: curr,
		}:
		default:
			bufPool.Put(bufArray)
			log.Printf("Can't keep up! Dropping packet from %s\n", sAddr.String())
		}
	}
}

func v4dispatcher(ctx context.Context, data chan *icmpReceived, icmpResponse chan *ICMPResponse,
	rawResponse chan *RawResponse) {
	for {
		select {
		case <-ctx.Done():
			return
		case resp := <-data:
			func() {
				defer bufPool.Put((*recvBuffer)(resp.data[:mtu:mtu]))

				var ip net.IP
				if _a, ok := resp.addr.(*net.IPAddr); ok {
					ip = _a.IP
				} else {
					log.Panicf("Unexpected resp.addr: <%T>(%v)\n", resp.addr, resp.addr)
				}
				r := &ICMPResponse{
					Received: resp.curr,
					AddrIP:   ip,
					Code:     257,
				}
				// read the body received
				msg, err := icmp.ParseMessage(1, resp.data) // iana.ProtocolICMP
				if err != nil {
					log.Printf("Failed parsing ICMP message: %s\n", err)
					return
				}
				var bodyData []byte
				switch body := msg.Body.(type) {
				// this message is EchoReply. Read identification info straightly.
				case *icmp.Echo:
					r.TargetIP = r.AddrIP
					r.ID = body.ID
					r.Seq = body.Seq
					r.Data = body.Data
					icmpResponse <- r
					return
				case *icmp.TimeExceeded:
					if msg.Code != 0 {
						if Debug {
							log.Printf("[DEBUG] Fragment reassembly time exceeded from %s\n", ip)
						}
						return
					} // We don't care Code 1: Fragment reassembly time exceeded.
					r.Code = 258
					bodyData = body.Data
					// let code below process
				case *icmp.DstUnreach:
					r.Code = msg.Code
					bodyData = body.Data
					// let code below process
				// this message may not be icmpReceived of our request.
				default:
					return
				}
				// Recover identification from response body which contains request header.
				// ICMP type 11 Data Structure, From IANA:
				// Data contains Source IP Header and First 8 bytes of payload
				// 20 bytes (In our case) IP Header of source message
				// 8 bytes  Head of Payload msg (full Echo msg in our case)
				if len(bodyData) < 28 {
					if Debug {
						log.Printf("[DEBUG] Response body from %s too short (%d < 28), can't recover source.\n", ip, len(bodyData))
					}
					return
				}
				head, err := ipv4.ParseHeader(bodyData[:20])
				if err != nil {
					if Debug {
						log.Printf("[DEBUG] Corrupted ipv4 header in response body from %s: %s.\n", ip, err)
					}
					return
				}
				r.TargetIP = head.Dst.To16()
				if head.Protocol == 1 { // iana.ProtocolICMP
					msgSend, err := icmp.ParseMessage(1, bodyData[20:]) // iana.ProtocolICMP
					if err != nil {
						if Debug {
							log.Printf("[DEBUG] Corrupted icmp header in response body from %s: %s.\n", ip, err)
						}
						return
					}
					// discard ICMP but not Echo message. That can't be response of our packets
					if sendBody, ok := msgSend.Body.(*icmp.Echo); ok {
						r.ID = sendBody.ID
						r.Seq = sendBody.Seq
						r.Data = sendBody.Data
						icmpResponse <- r
					} else if Debug {
						log.Printf("[DEBUG] Response body of a %T packet from %s ignored.\n", msgSend.Body, ip)
					}
				} else {
					// request not ICMP Protocol. Let rawResponse dispatcher process it.
					rawResponse <- &RawResponse{
						AddrIP:   r.AddrIP,
						Received: r.Received,
						TargetIP: r.TargetIP,
						Protocol: head.Protocol,
						Code:     r.Code,
						Fragment: bodyData[20:],
					}
				}
			}()
		}
	}
}

func v6dispatcher(ctx context.Context, data chan *icmpReceived, icmpResponse chan *ICMPResponse,
	rawResponse chan *RawResponse) {
	for {
		select {
		case <-ctx.Done():
			return
		case resp := <-data:
			func() {
				defer bufPool.Put((*recvBuffer)(resp.data[:mtu:mtu]))

				var ip net.IP
				if _a, ok := resp.addr.(*net.IPAddr); ok {
					ip = _a.IP
				} else {
					log.Panicf("Unexpected resp.addr: <%T>(%v)\n", resp.addr, resp.addr)
				}
				r := &ICMPResponse{
					Received: resp.curr,
					AddrIP:   ip,
					Code:     257,
				}
				// read the body received
				msg, err := icmp.ParseMessage(58, resp.data) // iana.ProtocolIPv6ICMP
				if err != nil {
					log.Printf("Failed parsing ICMPv6 message: %s\n", err)
					return
				}
				var bodyData []byte
				switch body := msg.Body.(type) {
				// this message is EchoReply. Read identification info straightly.
				case *icmp.Echo:
					r.TargetIP = r.AddrIP
					r.ID = body.ID
					r.Seq = body.Seq
					r.Data = body.Data
					icmpResponse <- r
					return
				case *icmp.TimeExceeded:
					if msg.Code != 0 {
						if Debug {
							log.Printf("[DEBUG] Fragment reassembly time exceeded from %s\n", ip)
						}
						return
					} // We don't care Code 1: Fragment reassembly time exceeded.
					r.Code = 258
					bodyData = body.Data
					// let code below process
				case *icmp.DstUnreach:
					r.Code = msg.Code
					bodyData = body.Data
					// let code below process
				// this message may not be icmpReceived of our request.
				default:
					return
				}
				// Recover identification from response body which contains request header.
				// ICMPv6 type 3 Data Part Structure, From IANA:
				// Data contains Source IP Header and First 8 bytes of payload
				// 40 bytes (In our case) IPv6 Header of source message
				// 8 bytes  Head of Payload msg (full Echo msg in our case)
				if len(bodyData) < 48 {
					if Debug {
						log.Printf("[DEBUG] Response body from %s too short (%d < 48), can't recover source.\n", ip, len(bodyData))
					}
					return
				}
				head, err := ipv6.ParseHeader(bodyData[:40])
				if err != nil {
					if Debug {
						log.Printf("[DEBUG] Corrupted ipv6 header in response body from %s: %s.\n", ip, err)
					}
					return
				}
				r.TargetIP = head.Dst.To16()
				if head.NextHeader == 58 { // iana.ProtocolIPv6ICMP
					msgSend, err := icmp.ParseMessage(58, bodyData[40:]) // iana.ProtocolIPv6ICMP
					if err != nil {
						if Debug {
							log.Printf("[DEBUG] Corrupted icmp header in response body from %s: %s.\n", ip, err)
						}
						return
					}
					// discard ICMPv6 but not Echo message. That can't be response of our packets
					if sendBody, ok := msgSend.Body.(*icmp.Echo); ok {
						r.ID = sendBody.ID
						r.Seq = sendBody.Seq
						r.Data = sendBody.Data
						icmpResponse <- r
					} else if Debug {
						log.Printf("[DEBUG] Response body of a %T packet from %s ignored.\n", msgSend.Body, ip)
					}
				} else {
					// request not ICMPv6 Protocol. Let rawResponse icmpDispatcher process it.
					rawResponse <- &RawResponse{
						AddrIP:   r.AddrIP,
						Received: r.Received,
						TargetIP: r.TargetIP,
						Protocol: head.NextHeader,
						Code:     r.Code,
						Fragment: bodyData[40:],
					}
				}
			}()
		}
	}
}

// GetICMPManager return ICMPManager to caller.
// As listening to ICMP will receive all ICMP packet,
// there will be only one manager in the whole process.
func GetICMPManager() *ICMPManager {
	once.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		manager = &ICMPManager{
			queue:   NewCMap(4),
			counter: 0,
			ctx:     ctx,
			cancel:  cancel,
		}
		resp4 := make(chan *icmpReceived, 1024)
		resp6 := make(chan *icmpReceived, 1024)
		result4 := make(chan *ICMPResponse, 1024)
		result6 := make(chan *ICMPResponse, 1024)
		raw4 := make(chan *RawResponse, 1024)
		raw6 := make(chan *RawResponse, 1024)
		conn4, err := icmp.ListenPacket("ip4:icmp", bind.LAddr4().String())
		if err != nil {
			log.Fatalf("Can't listen to ICMP: %s\n", err)
		}
		manager.pConn4 = conn4
		conn6, err := icmp.ListenPacket("ip6:ipv6-icmp", bind.LAddr6().String())
		if err != nil {
			log.Fatalf("Can't listen to ICMPv6: %s\n", err)
		}
		manager.pConn6 = conn6
		go v4dispatcher(ctx, resp4, result4, raw4)
		go v6dispatcher(ctx, resp6, result6, raw6)
		go receiver(ctx, conn4, resp4)
		go receiver(ctx, conn6, resp6)
		go manager.icmpDispatcher(result4, result6)
		go manager.rawDispatcher(raw4, raw6)
		// warm-up
		empty := make([]byte, 56)
		addr, _ := net.ResolveIPAddr("", "127.0.0.1")
		<-manager.Issue(addr, 100, time.Second, ICMPPayload{ID: 0, Seq: 0, Data: empty})
		addr, _ = net.ResolveIPAddr("", "::1")
		<-manager.Issue(addr, 100, time.Second, ICMPPayload{ID: 0, Seq: 0, Data: empty})

		if Debug {
			go func() {
				for range time.Tick(time.Minute) {
					sent := atomic.SwapUint32(&manager.sent, 0)
					recv := atomic.SwapUint32(&manager.received, 0)
					log.Printf("[DEBUG] Sent %d ICMP packets, received %d ICMP packets for last minute.\n", sent, recv)
				}
			}()
		}
	})
	return manager
}

// Issue an ICMP echo request. return a channel to send result back
func (mgr *ICMPManager) Issue(ip net.Addr, ttl int, timeout time.Duration, payload ICMPPayload) (delivery chan *Result) {
	ipAddr, ok := ip.(*net.IPAddr)
	if !ok {
		return nil
	}
	dest := ipAddr.IP.To4()
	v4 := true
	if dest == nil {
		v4 = false
	}
	dest = ipAddr.IP.To16()

	if payload.ID == -1 {
		payload.ID = rand.Intn(1 << 16)
	}

	if payload.Seq == -1 {
		payload.Seq = int((atomic.AddUint32(&mgr.counter, 1) - 1) & 0xffff)
	}

	var msg []byte
	echo := icmp.Message{
		Code: 0,
		Body: &icmp.Echo{
			ID:   payload.ID,
			Seq:  payload.Seq,
			Data: payload.Data,
		}}

	if v4 {
		echo.Type = ipv4.ICMPTypeEcho
	} else {
		echo.Type = ipv6.ICMPTypeEchoRequest
	}

	msg, _ = echo.Marshal(nil)

	delivery = make(chan *Result, 1)
	mgr.queue.Set((payload.ID<<16)|payload.Seq, &ICMPRequest{
		ICMPPayload: payload,
		TargetIP:    dest,
		delivery:    delivery,
	}, timeout)

	if v4 {
		mgr.lc4.Lock()
		if err := mgr.pConn4.IPv4PacketConn().SetTTL(ttl); err != nil {
			mgr.lc4.Unlock()
			return nil
		}
		_, _ = mgr.pConn4.WriteTo(msg, ipAddr)
		mgr.lc4.Unlock()
	} else {
		mgr.lc6.Lock()
		if err := mgr.pConn6.IPv6PacketConn().SetHopLimit(ttl); err != nil {
			mgr.lc6.Unlock()
			return nil
		}
		_, _ = mgr.pConn6.WriteTo(msg, ipAddr)
		mgr.lc6.Unlock()
	}

	if Debug {
		atomic.AddUint32(&manager.sent, 1)
	}
	return
}

// icmpDispatcher send Result back to their caller
func (mgr *ICMPManager) icmpDispatcher(v4, v6 chan *ICMPResponse) {
	ticker := time.NewTicker(100 * time.Millisecond)
	var last fasttime.Time
	for {
		now := fasttime.Now()
		var response *ICMPResponse
		select {
		case response = <-v4:
		case response = <-v6:
		case <-ticker.C:
		}

		if response != nil {
			key := response.ID<<16 | response.Seq
			if request, exists := mgr.queue.Get(key); exists {
				if request.Deliver(response) {
					mgr.queue.Remove(key)
				}
			} else if Debug {
				log.Printf("[DEBUG] Received ICMP response at %d not found in registry: "+
					"From %s in response of icmp echo to %s, seq %d, id %d, code %d\n",
					response.Received, response.AddrIP, response.TargetIP, response.Seq, response.ID, response.Code)
			}
		}

		if now.Since(last) < 50*time.Millisecond {
			continue
		}

		last = now
		timeout := make([]int, 0)
		for t := range mgr.queue.IterBuffered() {
			if t.Val.Passed(now) {
				t.Val.Deliver(nil)
				if Debug {
					if t.Val.Passed(now.Add(-time.Minute)) {
						timeout = append(timeout, t.Key)
					}
				} else {
					timeout = append(timeout, t.Key)
				}
			}
		}
		for _, key := range timeout {
			mgr.queue.Remove(key)
		}
		// just cleaned. No need to do it again.
		select {
		case <-ticker.C:
		default:
		}
	}
}

// rawDispatcher send RawResponse back to registered listener
func (mgr *ICMPManager) rawDispatcher(v4, v6 chan *RawResponse) {
	for {
		var response *RawResponse
		select {
		case response = <-v4:
		case response = <-v6:
		}
		// if listener for such protocol is presented
		if channel, ok := mgr.extListener[response.Protocol]; ok {
			channel <- response
		}
	}
}

func (mgr *ICMPManager) Flush() {
	queue := NewCMap(4)
	queue = (*ConMapRequest)(atomic.SwapPointer((*unsafe.Pointer)((unsafe.Pointer)(&mgr.queue)), unsafe.Pointer(queue)))
	for t := range mgr.queue.IterBuffered() {
		t.Val.Deliver(nil)
	}
}

func (mgr *ICMPManager) Finish() {
	mgr.cancel()
}

func FinishICMPManager() {
	if manager != nil && manager.ctx.Done() != nil {
		select {
		case <-manager.ctx.Done():
		default:
			manager.cancel()
		}
	}
}
