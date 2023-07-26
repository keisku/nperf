package time

import "time"

func MicroSeconds(t time.Time) int64 {
	return t.UnixNano() / 1000
}
