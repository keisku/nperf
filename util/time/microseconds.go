package time

import "time"

func MicroSeconds(t time.Time) uint64 {
	return uint64(t.UnixNano() / 1000)
}
