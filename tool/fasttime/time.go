package fasttime

import "time"
import _ "unsafe"

//go:linkname runtimeNano runtime.nanotime
func runtimeNano() int64

type (
	Time     int64
	Duration = time.Duration
)

func Now() Time {
	return Time(runtimeNano())
}

func (t Time) Since(s Time) Duration {
	return time.Duration(t - s)
}

func (t Time) Add(d Duration) Time {
	return t + Time(d)
}

func (t Time) Sub(s Time) Duration {
	return Duration(t - s)
}

func (t Time) Before(s Time) bool {
	return t < s
}
