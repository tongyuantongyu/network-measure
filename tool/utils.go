package tool

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"time"
)

func getContext(span uint64) (context.Context, context.CancelFunc) {
	if span > 30*1000 {
		return context.WithTimeout(context.Background(), 30*time.Second)
	} else if span < 10 {
		return context.WithTimeout(context.Background(), 10*time.Millisecond)
	} else {
		return context.WithTimeout(context.Background(), time.Duration(span)*time.Millisecond)
	}
}

func getNetwork(network string, family int32, host string) (string, error) {
	if family == 0 && host != "" {
		ip, err := netip.ParseAddr(host)
		if err != nil {
			ipp, err := netip.ParseAddrPort(host)
			if err == nil {
				ip = ipp.Addr()
			}
		}
		if ip.IsValid() {
			switch {
			case ip.Is4():
				family = 4
			case ip.Is6():
				family = 6
			}
		}
	}
	switch family {
	case 4:
		network += "4"
	case 6:
		network += "6"
	case 0:
	default:
		return "", errors.New("bad family number")
	}

	return network, nil
}

var id uint32

func getICMPID() int {
	return int(atomic.AddUint32(&id, 1) & 0xffff)
}
