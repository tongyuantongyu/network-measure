package bind

import (
	"fmt"
	"log"
	"net"
	"strings"
)

var (
	v4 *net.IPAddr
	v6 *net.IPAddr
)

func parseIPAddr(str string) *net.IPAddr {
	if idx := strings.LastIndex(str, "%"); idx != -1 {
		ip := net.ParseIP(str[:idx])
		if ip.To4() != nil {
			return nil
		}
		return &net.IPAddr{IP: ip, Zone: str[idx+1:]}
	}

	if ip := net.ParseIP(str); ip != nil {
		return &net.IPAddr{IP: ip}
	}

	return nil
}

func Parse(ips []string) error {
	var addrs []net.Addr

	if len(ips) == 1 {
		str := ips[0]
		ips = ips[1:]
		if ip := parseIPAddr(str); ip == nil {
			if iface, err := net.InterfaceByName(str); err == nil {
				if addrs, err = iface.Addrs(); err != nil {
					return fmt.Errorf("can't list addresses of interface '%s': %w", str, err)
				}
			} else {
				return fmt.Errorf("invalid ip address '%s'", str)
			}
		} else {
			addrs = append(addrs, ip)
		}
	}

	for _, str := range ips {
		if ip := parseIPAddr(str); ip == nil {
			return fmt.Errorf("invalid ip address '%s'", str)
		} else {
			addrs = append(addrs, ip)
		}
	}

	setIP := func(addr *net.IPAddr, isv6 bool) {
		var target **net.IPAddr
		var typ string
		if isv6 {
			target = &v6
			typ = "IPv6"
		} else {
			target = &v4
			typ = "IPv4"
		}

		if *target == nil {
			*target = addr
		} else {
			log.Printf("Ignored %s as %s is already selected as %s bind address. "+
				"Explicitly specify %s as the only %s bind address to use it.\n", addr, *target, typ, addr, typ)
		}
	}

	for _, addr := range addrs {
		switch addr := addr.(type) {
		case *net.IPAddr:
			setIP(addr, addr.IP.To4() == nil)
		case *net.IPNet:
			setIP(&net.IPAddr{IP: addr.IP}, addr.IP.To4() == nil)
		default:
			log.Printf("Got unexpected laddr: %s(%T). This should be reported.", addr, addr)
		}
	}

	return nil
}

func LAddr4() *net.IPAddr {
	return v4
}

func LAddr6() *net.IPAddr {
	return v6
}

func Set() bool {
	return v4 != nil || v6 != nil
}
