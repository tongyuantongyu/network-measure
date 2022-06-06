package fasttime

import "time"
import _ "unsafe"

//go:linkname runtimeNano runtime.nanotime
func runtimeNano() int64

type Time int64

func Now() Time {
	return Time(runtimeNano())
}

func (t Time) Since(s Time) time.Duration {
	return time.Duration(t - s)
}

func (t Time) Add(d time.Duration) Time {
	return t + Time(d)
}

func (t Time) Sub(s Time) time.Duration {
	return time.Duration(t - s)
}

func (t Time) Before(s Time) bool {
	return t < s
}
