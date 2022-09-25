package tool

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"net"
	"network-measure/bind"
	"strings"
	"time"
)

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#table-alpn-protocol-ids
var alpn = []string{
	"h3",
	"h2",

	"spdy/3",
	"spdy/2",
	"spdy/1",

	"http/1.1",
	"http/1.0",
	"http/0.9",

	"h2c",

	"stun.turn",
	"stun.nat-discovery",
	"webrtc",
	"c-webrtc",
	"ftp",
	"imap",
	"pop3",
	"managesieve",
	"coap",
	"xmpp-client",
	"xmpp-server",
	"acme-tls/1",
	"mqtt",
	"dot",
	"ntske/1",
	"sunrpc",
	"smb",
	"irc",
	"nntp",
	"nnsp",
	"doq",
}

var cipherSuite = []uint16{
	tls.TLS_RSA_WITH_RC4_128_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
}

var versionNames = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

var cipherSuiteNames = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:                      "TLS_RSA_WITH_RC4_128_SHA",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:                 "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:                  "TLS_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:                  "TLS_RSA_WITH_AES_256_CBC_SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:               "TLS_RSA_WITH_AES_128_CBC_SHA256",
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:               "TLS_RSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:               "TLS_RSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:              "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:          "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:          "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:                "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:           "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:       "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:         "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:         "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:         "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",

	tls.TLS_AES_128_GCM_SHA256:       "TLS_AES_128_GCM_SHA256",
	tls.TLS_AES_256_GCM_SHA384:       "TLS_AES_256_GCM_SHA384",
	tls.TLS_CHACHA20_POLY1305_SHA256: "TLS_CHACHA20_POLY1305_SHA256",
}

var ocspStatusNames = map[int]string{
	ocsp.Good:    "Good",
	ocsp.Revoked: "Revoked",
	ocsp.Unknown: "Unknown",
}

func TLS(q *TlsQ) (*TlsP, error) {
	if q.Wait < 10 {
		q.Wait = 10
	} else if q.Wait > 10000 {
		q.Wait = 10000
	}

	p := &TlsP{}

	network, err := getNetwork("tcp", q.Family, "")
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
		p.Reason = ReasonResolveFailed
		p.Error = err.Error()
		return p, nil
	}

	p.Resolved = addr.IP.String()

	d := net.Dialer{
		FallbackDelay: -1,
		KeepAlive:     -1,
	}

	if addr.IP.To4() != nil {
		if bind.LAddr4() != nil {
			d.LocalAddr = &net.TCPAddr{IP: bind.LAddr4().IP}
		}
	} else {
		if bind.LAddr6() != nil {
			d.LocalAddr = &net.TCPAddr{IP: bind.LAddr6().IP, Zone: bind.LAddr6().Zone}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(q.Wait)*time.Millisecond)
	defer cancel()
	conn, err := d.DialContext(ctx, network, addr.String())
	if err != nil {
		p.Reason = ReasonDialFailed
		p.Error = err.Error()
		return p, nil
	}

	var usingAlpn = alpn
	if len(q.ALPN) != 0 {
		usingAlpn = q.ALPN
	}

	sni := q.Address
	if q.SNI != nil {
		sni = *q.SNI
	}

	cli := tls.Client(conn, &tls.Config{
		NextProtos:         usingAlpn,
		ServerName:         sni,
		InsecureSkipVerify: true,
		CipherSuites:       cipherSuite,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
	})

	if err = cli.HandshakeContext(ctx); err != nil {
		p.Reason = ReasonHandshakeFailed
		p.Error = err.Error()
		return p, nil
	}

	state := cli.ConnectionState()
	var exist bool

	if p.Version, exist = versionNames[state.Version]; !exist {
		return nil, fmt.Errorf("unknown tls version: %x", state.Version)
	}

	if p.Suite, exist = cipherSuiteNames[state.CipherSuite]; !exist {
		return nil, fmt.Errorf("unknown cipher suite: %x", state.Version)
	}

	p.ALPN = state.NegotiatedProtocol

	srvCert := state.PeerCertificates[0]
	p.AltNames = make([]string, 0, len(srvCert.DNSNames)+len(srvCert.IPAddresses))
	p.AltNames = append(p.AltNames, srvCert.DNSNames...)

	for _, ip := range srvCert.IPAddresses {
		p.AltNames = append(p.AltNames, ip.String())
	}

	opts := x509.VerifyOptions{
		CurrentTime:   time.Now(),
		Intermediates: x509.NewCertPool(),
	}

	p.Certificates.Provided = make([]Certificate, 0, len(state.PeerCertificates))
	for i := len(state.PeerCertificates); i > 0; i-- {
		cert := state.PeerCertificates[i-1]
		hash := sha256.Sum256(cert.Raw)
		data := Certificate{
			Subject:            cert.Subject.String(),
			Issuer:             cert.Issuer.String(),
			NotBefore:          cert.NotBefore,
			NotAfter:           cert.NotAfter,
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
			Hash:               hex.EncodeToString(hash[:]),
		}

		_, err = cert.Verify(opts)
		data.Valid = err == nil
		p.Certificates.Provided = append(p.Certificates.Provided, data)
		if i != 1 {
			opts.Intermediates.AddCert(cert)
		}
	}

	opts.DNSName = sni

	chains, err := srvCert.Verify(opts)
	if err != nil {
		p.Reason = ReasonVerifyFailed
		p.Error = err.Error()
		return p, nil
	}

	chain := chains[0]
	p.Certificates.Chain = make([]Certificate, 0, len(chain))
	for i := len(chain); i > 0; i-- {
		cert := chain[i-1]
		hash := sha256.Sum256(cert.Raw)
		p.Certificates.Chain = append(p.Certificates.Chain, Certificate{
			Subject:            cert.Subject.String(),
			NotBefore:          cert.NotBefore,
			NotAfter:           cert.NotAfter,
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
			Valid:              true,
			Hash:               hex.EncodeToString(hash[:]),
		})
	}

	if len(state.OCSPResponse) > 0 {
		p.OCSPInfo.Present = true

		if len(chain) >= 2 {
			p.OCSPInfo.Present = true
			response, err := ocsp.ParseResponseForCert(state.OCSPResponse, chain[0], chain[1])
			if err != nil {
				p.Reason = ReasonOCSPFailed
				p.Error = err.Error()
				return p, nil
			} else {
				if p.OCSPInfo.Status, exist = ocspStatusNames[response.Status]; !exist {
					return nil, fmt.Errorf("unknown ocsp status: %x", state.Version)
				}
				p.OCSPInfo.ThisUpdate = &response.ThisUpdate
				p.OCSPInfo.NextUpdate = &response.NextUpdate
			}
		} else {
			p.OCSPInfo.Status = "Unrelated"
		}
	}

	p.Success = true
	_ = cli.Close()
	return p, nil
}
