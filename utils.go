package main

import (
	"context"
	"errors"
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

func getNetwork(network string, family int32) (string, error) {
	switch family {
	case 4:
		network += "4"
	case 6:
		network += "6"
	case 0:
		break
	default:
		return "", errors.New("bad family number")
	}

	return network, nil
}
