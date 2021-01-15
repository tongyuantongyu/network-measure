package main

type ResolveQ struct {
	Address string `json:"address" binding:"required"`
	Family  int32  `json:"family"`

	Wait uint64 `json:"wait"`

	TimeStamp uint64 `json:"stamp" binding:"required"`
	Nonce     uint64 `json:"nonce" binding:"required"`
}

type ResolveP struct {
	Data []string `json:"data"`
}

// types for ping

type PingQ struct {
	Address string `json:"address" binding:"required"`
	Family  int32  `json:"family"`

	Wait     uint64 `json:"wait"`
	Interval uint64 `json:"interval"`
	Times    uint64 `json:"times" binding:"required"`

	TimeStamp uint64 `json:"stamp" binding:"required"`
	Nonce     uint64 `json:"nonce" binding:"required"`
}

type PingPEntry struct {
	IP      string  `json:"ip"`
	Code    int     `json:"code"`
	Latency float64 `json:"latency"`
}

type PingP struct {
	Resolved string       `json:"resolved"`
	Data     []PingPEntry `json:"data"`
}

// types for tcp ping

type TCPingQ struct {
	Address string `json:"address" binding:"required"`
	Family  int32  `json:"family"`
	Port    uint16 `json:"port" binding:"required"`

	Wait     uint64 `json:"wait"`
	Interval uint64 `json:"interval"`
	Times    uint64 `json:"times" binding:"required"`

	TimeStamp uint64 `json:"stamp" binding:"required"`
	Nonce     uint64 `json:"nonce" binding:"required"`
}

type TCPingPEntry struct {
	Success bool    `json:"success"`
	Latency float64 `json:"latency"`
}

type TCPingP struct {
	Resolved string         `json:"resolved"`
	Data     []TCPingPEntry `json:"data"`
}

// types for mtr

type MtrQ struct {
	Address string `json:"address" binding:"required"`
	Family  int32  `json:"family"`

	Wait     uint64 `json:"wait"`
	Interval uint64 `json:"interval" binding:"required"`
	Times    uint64 `json:"times" binding:"required"`
	MaxHop   uint64 `json:"max_hop" binding:"required"`
	RDNS     bool   `json:"rdns"`

	TimeStamp uint64 `json:"stamp" binding:"required"`
	Nonce     uint64 `json:"nonce" binding:"required"`
}

type MtrPEntry struct {
	Address string  `json:"address"`
	RDNS    string  `json:"rdns"`
	Code    int     `json:"code"`
	Latency float64 `json:"latency"`
}

type MtrP struct {
	Resolved string        `json:"resolved"`
	Data     [][]MtrPEntry `json:"data"`
}

// types for speed test

type SpeedQ struct {
	URL    string `json:"url" binding:"required"`
	Family int32  `json:"family"`

	Wait     uint64 `json:"wait" binding:"required"`
	Span     uint64 `json:"span" binding:"required"`
	Interval uint64 `json:"interval" binding:"required"`

	TimeStamp uint64 `json:"stamp" binding:"required"`
	Nonce     uint64 `json:"nonce" binding:"required"`
}

type SpeedPEntry struct {
	TimePoint float64 `json:"point"`
	Received  uint64  `json:"received"`
}

type SpeedP struct {
	Resolved string `json:"resolved"`

	Latency  float64       `json:"latency"`
	Elapsed  float64       `json:"elapsed"`
	Received uint64        `json:"received"`
	Data     []SpeedPEntry `json:"data"`
}
