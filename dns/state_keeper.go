package dns

import (
	"time"

	"golang.org/x/exp/slog"
)

// https://github.com/DataDog/datadog-agent/blob/599c6147dafafbb64772a238c679e1a56b1e0234/pkg/network/dns/stats.go#L63
type stateKeeper struct{}

func (s *stateKeeper) processPacket(packet Packet, t time.Time) {
	// https://github.com/DataDog/datadog-agent/blob/599c6147dafafbb64772a238c679e1a56b1e0234/pkg/network/dns/stats.go#L106
	slog.Info("DNS state keeper process a packet", packet.LogAttr(), slog.Time("packet processed", t))
	slog.Warn("DNS state keeper is not implemented yet")
}
