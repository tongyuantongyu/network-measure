package icmp

import (
	"context"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"math/rand"
	"net"
	"sync"
	"time"
)

// An ICMPRequest represents an ICMPRequest issued by ping or trace for listener
// to get corresponding Result
type ICMPRequest struct {
	// Seq used to identify request, and will be returned in Result to mark
	Seq int
	// extend identify field
	ID int
	// target ip of the request, extend identify field
	TargetIP net.IP
	// return timeout Result if Deadline passed.
	Deadline time.Time
	// request issue time
	IssueTime time.Time
	// channel to return result
	delivery chan *Result
}

func (r *ICMPRequest) SetTimeout(duration time.Duration) {
	r.IssueTime = time.Now()
	r.Deadline = r.IssueTime.Add(duration)
}

func (r ICMPRequest) Passed(time time.Time) bool {
	return r.Deadline.Before(time)
}

func (r ICMPRequest) Deliver(response Response) bool {
	if response == nil {
		r.delivery <- &Result{
			Code: 256,
		}
		close(r.delivery)
		return true
	}
	ID, TargetIP := response.GetIdentifier()
	if ID == r.ID && TargetIP.Equal(r.TargetIP) {
		AddrIP, Received, Code := response.GetInformation()
		if r.Passed(Received) {
			r.delivery <- &Result{
				Code: 256,
			}
		} else {
			r.delivery <- &Result{
				AddrIP:  AddrIP,
				Latency: Received.Sub(r.IssueTime),
				Code:    Code,
			}
		}
		close(r.delivery)
		return true
	}
	return false
}

// An ICMPResponse represents an ICMPResponse (EchoReply, TimeExceed or DstUnreachable)
type ICMPResponse struct {
	// Seq used to identify request
	Seq int
	// extend identify field
	ID int
	// response source ip
	AddrIP net.IP
	// time passed from request time
	Received time.Time
	// target ip of the request
	TargetIP net.IP
	// Code of ICMP destination unreachable message response
	Code int
}

func (I ICMPResponse) GetIdentifier() (int, net.IP) {
	return I.ID, I.TargetIP
}

func (I ICMPResponse) GetInformation() (net.IP, time.Time, int) {
	return I.AddrIP, I.Received, I.Code
}

// A RawResponse represents an ICMPResponse (TimeExceed or DstUnreachable) of none-ICMP request
type RawResponse struct {
	// response source ip
	AddrIP net.IP
	// time passed from request time
	Received time.Time
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
	// counter will fill the sequence field of the request (precisely 16bits)
	// to identify packet. it will be increased for each call and can hold at
	// most 65536 concurrent pending requests.
	counter uint16
	// l is the mutex to make counter increment thread safe.
	l sync.Mutex
	// context to send the manager stop message
	ctx context.Context
	// function to call to stop the manager
	cancel context.CancelFunc
	// icmp packet conn of related network
	pConn4 *icmp.PacketConn
	pConn6 *icmp.PacketConn
}

var manager *ICMPManager
var once sync.Once

// listen to ICMP socket to receive packet
func ICMPv4Receiver(conn *icmp.PacketConn, wait time.Duration, icmpResponse chan *ICMPResponse,
	rawResponse chan *RawResponse, ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	default:
	}
	//conn, err := icmp.ListenPacket("ip4:icmp", "")
	//if err != nil {
	//    return
	//}
	// wait `wait` to receive some body
	if err := conn.SetDeadline(time.Now().Add(wait)); err != nil {
		return
	}
	readBytes := make([]byte, 1500) // max MTU
	n, sAddr, connErr := conn.ReadFrom(readBytes)
	now := time.Now()
	go ICMPv4Receiver(conn, wait, icmpResponse, rawResponse, ctx)
	if connErr != nil || sAddr == nil {
		return
	}
	var ip net.IP
	if _a, ok := sAddr.(*net.IPAddr); ok {
		ip = _a.IP
	} else {
		return
	}
	r := &ICMPResponse{
		Received: now,
		AddrIP:   ip,
		Code:     257,
	}
	// read the body received
	msg, err := icmp.ParseMessage(1, readBytes[:n]) // iana.ProtocolICMP
	if err != nil {
		return
	}
	var bodyData []byte
	switch body := msg.Body.(type) {
	// this message is EchoReply. Read identification info straightly.
	case *icmp.Echo:
		r.TargetIP = r.AddrIP
		r.ID = body.ID
		r.Seq = body.Seq
		icmpResponse <- r
		return
	case *icmp.TimeExceeded:
		if msg.Code != 0 {
			return
		} // We don't care Code 1: Fragment reassembly time exceeded.
		r.Code = 258
		bodyData = body.Data
		// let code below process
	case *icmp.DstUnreach:
		r.Code = msg.Code
		bodyData = body.Data
		// let code below process
	// this message may not be icmpResponse of our request.
	default:
		return
	}
	// Recover identification from response body which contains request header.
	// ICMP type 11 Data Structure, From IANA:
	// Data contains Source IP Header and First 8 bytes of payload
	// 20 bytes (In our case) IP Header of source message
	// 8 bytes  Head of Payload msg (full Echo msg in our case)
	if len(bodyData) < 28 {
		return
	}
	head, err := ipv4.ParseHeader(bodyData[:20])
	if err != nil {
		return
	}
	r.TargetIP = head.Dst.To16()
	if head.Protocol == 1 { // iana.ProtocolICMP
		msgSend, err := icmp.ParseMessage(1, bodyData[20:28]) // iana.ProtocolICMP
		if err != nil {
			return
		}
		// discard ICMP but not Echo message. That can't be response of our packets
		if sendBody, ok := msgSend.Body.(*icmp.Echo); ok {
			r.ID = sendBody.ID
			r.Seq = sendBody.Seq
			icmpResponse <- r
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
}

// listen to ICMPv6 socket to receive packet
func ICMPv6Receiver(conn *icmp.PacketConn, wait time.Duration, icmpResponse chan *ICMPResponse,
	rawResponse chan *RawResponse, ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	default:
	}
	//conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "")
	//if err != nil {
	//    return
	//}
	// wait `wait` to receive some body
	if err := conn.SetDeadline(time.Now().Add(wait)); err != nil {
		return
	}
	readBytes := make([]byte, 1500) // max MTU
	n, sAddr, connErr := conn.ReadFrom(readBytes)
	now := time.Now()
	go ICMPv6Receiver(conn, wait, icmpResponse, rawResponse, ctx)
	if connErr != nil || sAddr == nil {
		return
	}
	var ip net.IP
	if _a, ok := sAddr.(*net.IPAddr); ok {
		ip = _a.IP
	} else {
		return
	}
	r := &ICMPResponse{
		Received: now,
		AddrIP:   ip,
		Code:     257,
	}
	// read the body received
	msg, err := icmp.ParseMessage(58, readBytes[:n]) // iana.ProtocolIPv6ICMP
	if err != nil {
		return
	}
	var bodyData []byte
	switch body := msg.Body.(type) {
	// this message is EchoReply. Read identification info straightly.
	case *icmp.Echo:
		r.TargetIP = r.AddrIP
		r.ID = body.ID
		r.Seq = body.Seq
		icmpResponse <- r
		return
	case *icmp.TimeExceeded:
		if msg.Code != 0 {
			return
		} // We don't care Code 1: Fragment reassembly time exceeded.
		r.Code = 258
		bodyData = body.Data
		// let code below process
	case *icmp.DstUnreach:
		r.Code = msg.Code
		bodyData = body.Data
		// let code below process
	// this message may not be icmpResponse of our request.
	default:
		return
	}
	// Recover identification from response body which contains request header.
	// ICMPv6 type 3 Data Part Structure, From IANA:
	// Data contains Source IP Header and First 8 bytes of payload
	// 40 bytes (In our case) IPv6 Header of source message
	// 8 bytes  Head of Payload msg (full Echo msg in our case)
	if len(bodyData) < 48 {
		return
	}
	head, err := ipv6.ParseHeader(bodyData[:40])
	if err != nil {
		return
	}
	r.TargetIP = head.Dst.To16()
	if head.NextHeader == 58 { // iana.ProtocolIPv6ICMP
		msgSend, err := icmp.ParseMessage(58, bodyData[40:48]) // iana.ProtocolIPv6ICMP
		if err != nil {
			return
		}
		// discard ICMPv6 but not Echo message. That can't be response of our packets
		if sendBody, ok := msgSend.Body.(*icmp.Echo); ok {
			r.ID = sendBody.ID
			r.Seq = sendBody.Seq
			icmpResponse <- r
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
}

// return ICMPManager to caller. As listening to ICMP will receive all ICMP
// packet, there will be only one manager in the whole process.
func GetICMPManager() *ICMPManager {
	once.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		manager = &ICMPManager{
			queue:   NewCMap(32),
			counter: 0,
			ctx:     ctx,
			cancel:  cancel,
		}
		result4 := make(chan *ICMPResponse, 1024)
		result6 := make(chan *ICMPResponse, 1024)
		raw4 := make(chan *RawResponse, 1024)
		raw6 := make(chan *RawResponse, 1024)
		conn4, err := icmp.ListenPacket("ip4:icmp", "")
		if err != nil {
			panic(fmt.Sprintf("Can't listen to ICMP: %s", err))
		}
		manager.pConn4 = conn4
		conn6, err := icmp.ListenPacket("ip6:ipv6-icmp", "")
		if err != nil {
			panic(fmt.Sprintf("Can't listen to ICMPv6: %s", err))
		}
		manager.pConn6 = conn6
		go ICMPv4Receiver(conn4, 1000*time.Millisecond, result4, raw4, ctx)
		go ICMPv6Receiver(conn6, 1000*time.Millisecond, result6, raw6, ctx)
		go manager.icmpDispatcher(result4, result6)
		go manager.rawDispatcher(raw4, raw6)
		// warm-up
		addr, _ := net.ResolveIPAddr("", "127.0.0.1")
		manager.Issue(addr, 100, time.Second)
		addr, _ = net.ResolveIPAddr("", "::1")
		manager.Issue(addr, 100, time.Second)
	})
	return manager
}

// Issue an ICMP echo request. return a channel to send result back
func (mgr *ICMPManager) Issue(ip net.Addr, ttl int, timeout time.Duration) (delivery chan *Result) {
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

	mgr.l.Lock()
	count := mgr.counter
	mgr.counter++
	mgr.l.Unlock()

	id := rand.Intn(1 << 16)
	var msg []byte
	if v4 {
		echo := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   id,
				Seq:  int(count),
				Data: nil,
			}}
		msg, _ = echo.Marshal(nil)
	} else {
		echo := icmp.Message{
			Type: ipv6.ICMPTypeEchoRequest,
			Code: 0,
			Body: &icmp.Echo{
				ID:   id,
				Seq:  int(count),
				Data: nil,
			}}
		msg, _ = echo.Marshal(nil)
	}

	delivery = make(chan *Result, 1)
	mgr.queue.Set(int(count), &ICMPRequest{
		Seq:      int(count),
		ID:       id,
		TargetIP: dest,
		delivery: delivery,
	}, timeout)

	if v4 {
		if err := mgr.pConn4.IPv4PacketConn().SetTTL(ttl); err != nil {
			return nil
		}
		_, _ = mgr.pConn4.WriteTo(msg, ipAddr)
	} else {
		if err := mgr.pConn6.IPv6PacketConn().SetHopLimit(ttl); err != nil {
			return nil
		}
		_, _ = mgr.pConn6.WriteTo(msg, ipAddr)
	}

	return
}

// icmpDispatcher send Result back to their caller
func (mgr *ICMPManager) icmpDispatcher(v4, v6 chan *ICMPResponse) {
	ticker := time.NewTicker(10 * time.Millisecond)
	for {
		now := time.Now()
		var response *ICMPResponse = nil
		select {
		case response = <-v4:
		case response = <-v6:
		case <-ticker.C:
		}

		if response != nil {
			if request, exists := mgr.queue.Get(response.Seq); exists {
				if request.Deliver(response) {
					mgr.queue.Remove(response.Seq)
				}
			}
		}

		timeout := make([]int, 0)
		for t := range mgr.queue.IterBuffered() {
			if t.Val.Passed(now) {
				timeout = append(timeout, t.Key)
				t.Val.Deliver(nil)
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
		var response *RawResponse = nil
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
