package main

import (
	"net"
)

func resolve(q *ResolveQ) (*ResolveP, error) {
	network, err := getNetwork("ip", q.Family)
	if err != nil {
		return nil, err
	}

	ctx, cancel := getContext(q.Wait)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupIP(ctx, network, q.Address)
	if err != nil {
		return nil, err
	}

	s := make(map[string]struct{})
	for _, addr := range addrs {
		s[addr.String()] = struct{}{}
	}

	r := &ResolveP{
		Data: make([]string, 0, len(s)),
	}

	for addr := range s {
		r.Data = append(r.Data, addr)
	}

	return r, nil
}
