package dns

import (
	"context"
	"fmt"
	"syscall"
	"time"

	"github.com/google/gopacket/afpacket"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/exp/slog"
)

type Monitor struct {
	sourceTPacket *afpacket.TPacket
	parser        *parser
}

func NewMonitor(config Config) (*Monitor, error) {
	tpacket, err := newTPacket()
	if err != nil {
		return nil, fmt.Errorf("create raw socket: %s", err)
	}
	return &Monitor{
		sourceTPacket: tpacket,
		parser:        newParser(config.QueryTypes),
	}, nil
}

func newTPacket() (*afpacket.TPacket, error) {
	tpacket, err := afpacket.NewTPacket(
		afpacket.OptPollTimeout(time.Second),
		// This setup will require ~4Mb that is mmap'd into the process virtual space
		// More information here: https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
		afpacket.OptFrameSize(4096),
		afpacket.OptBlockSize(4096*128),
		afpacket.OptNumBlocks(8),
	)
	if err != nil {
		return nil, fmt.Errorf("create raw socket: %s", err)
	}
	return tpacket, nil
}

// Run starts the Monitor until the context is canceled.
func (m *Monitor) Run(ctx context.Context) {
	m.pollPackets(ctx)
	<-ctx.Done()
	m.sourceTPacket.Close()
}

func (m *Monitor) pollPackets(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Millisecond)
	for {
		select {
		case <-ctx.Done():
			slog.Info("stop polling packets")
			return
		case <-ticker.C:
			data, captureInfo, err := m.sourceTPacket.ZeroCopyReadPacketData()

			// This is the error code returned when an operation on a non-blocking socket cannot be completed immediately.
			// It tells the program that the operation would have caused the process to be suspended,
			// and the process should try the operation again later.
			if err == syscall.EAGAIN {
				pollPacketEAGAIN.Add(ctx, 1)
				continue
			}
			if err == afpacket.ErrTimeout {
				pollPacketTimeout.Add(ctx, 1)
				slog.Debug("timeout while reading a packet")
				continue
			}
			if err != nil {
				pollPacketError.Add(ctx, 1, metric.WithAttributes(attribute.String("error", err.Error())))
				slog.Warn("read a packet", err)
				continue
			}

			if err := m.processPacket(data, captureInfo.Timestamp); err != nil {
				slog.Debug(fmt.Sprintf("retrieve DNS information form a received packet: %s", err))
			}
		}
	}
}

// processPacket retrieves DNS information from the received packet data.
func (m *Monitor) processPacket(data []byte, t time.Time) error {
	var packet Packet
	if err := m.parser.parse(data, &packet); err != nil {
		return fmt.Errorf("parse a DNS packet: %s", err)
	}
	return nil
}
