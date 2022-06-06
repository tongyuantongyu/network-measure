package tool

import "time"

type check struct {
	TimeStamp uint64 `json:"stamp" binding:"required"`
	Nonce     uint64 `json:"nonce" binding:"required"`
}

type ResolveQ struct {
	Address string `json:"address" binding:"required"`
	Family  int32  `json:"family"`

	Wait uint64 `json:"wait"`

	check
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

	check
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

	check
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

	check
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

	check
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

	Trace struct {
		DNS       float64 `json:"dns"`
		Conn      float64 `json:"conn"`
		TLS       float64 `json:"tls,omitempty"`
		Sent      float64 `json:"request_sent"`
		FirstByte float64 `json:"first_byte"`
	} `json:"trace"`
}

type TlsQ struct {
	Address string `json:"address" binding:"required"`
	Family  int32  `json:"family"`
	Port    uint16 `json:"port" binding:"required"`

	Suites []uint16 `json:"suites"`
	SNI    string   `json:"sni"`
	ALPN   []string `json:"alpn"`
	Wait   uint64   `json:"wait"`

	check
}

const (
	ReasonOK = iota
	ReasonResolveFailed
	ReasonDialFailed
	ReasonHandshakeFailed
	ReasonVerifyFailed
	ReasonOCSPFailed
)

type Certificate struct {
	Valid bool `json:"valid"`

	Subject string `json:"subject"`
	Issuer  string `json:"issuer,omitempty"`

	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`

	SignatureAlgorithm string `json:"signature_algorithm"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
}

type TlsP struct {
	Success bool   `json:"success"`
	Reason  uint32 `json:"reason"`
	Error   string `json:"error"`

	Resolved string `json:"resolved"`
	Version  string `json:"version"`
	Suite    string `json:"suite"`
	ALPN     string `json:"alpn"`

	Certificates struct {
		Provided []Certificate `json:"provided"`
		Chain    []Certificate `json:"chain"`
	} `json:"certificates"`

	AltNames []string `json:"alt_names"`

	OCSPInfo struct {
		Present    bool       `json:"present"`
		Status     string     `json:"status,omitempty"`
		ThisUpdate *time.Time `json:"this_update,omitempty"`
		NextUpdate *time.Time `json:"next_update,omitempty"`
	} `json:"ocsp_info"`
}
