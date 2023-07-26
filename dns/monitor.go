package dns

import (
	"context"
	"fmt"
	"syscall"
	"time"

	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	timeutil "github.com/keisku/nmon/util/time"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/exp/slog"
)

type Monitor struct {
	sourceTPacket *afpacket.TPacket
	parser        *parser
	queryStats    map[queryStatsKey]queryStatsValue
}

type queryStatsKey struct {
	key           Key
	transactionId uint16
}

type queryStatsValue struct {
	packetCapturedAt int64
	question         string
	queryType        layers.DNSType
}

func (v queryStatsValue) Attributes() []attribute.KeyValue {
	return []attribute.KeyValue{
		// NOTE:
		// - Don't add the packetCapturedAt to the attributes because it's high cardinality.
		attribute.String("question", v.question),
		attribute.String("query_type", v.queryType.String()),
	}
}

func (m *Monitor) recordQueryStats(packet Packet) error {
	queryStatsKey := queryStatsKey{
		key:           packet.key,
		transactionId: packet.transactionID,
	}

	if packet.typ == packetTypeQuery {
		if _, ok := m.queryStats[queryStatsKey]; !ok {
			m.queryStats[queryStatsKey] = queryStatsValue{
				packetCapturedAt: timeutil.MicroSeconds(packet.capturedAt),
				question:         packet.question.Get(),
				queryType:        packet.queryType,
			}
		}
		return nil
	}

	metricAttrs := append(m.queryStats[queryStatsKey].Attributes(), packet.Attributes()...)

	queryStats, ok := m.queryStats[queryStatsKey]
	if !ok {
		noCorrespondingResponse.Add(context.Background(), 1, metric.WithAttributes(metricAttrs...))
		return fmt.Errorf("no corresponding query entry for a response: %#v", packet.key)
	}

	delete(m.queryStats, queryStatsKey)

	latency := timeutil.MicroSeconds(packet.capturedAt) - queryStats.packetCapturedAt
	queryLatency.Record(context.Background(), latency, metric.WithAttributes(metricAttrs...))
	queryLatencyGaugeCh <- datapoint[int64]{value: latency, attributes: metricAttrs}
	select {
	case queryLatencyGaugeCh <- datapoint[int64]{value: latency, attributes: metricAttrs}:
	default:
		slog.Warn("failed to send a datapoint to the channel")
	}
	return nil
}

func NewMonitor(config Config) (*Monitor, error) {
	tpacket, err := newTPacket()
	if err != nil {
		return nil, fmt.Errorf("create raw socket: %s", err)
	}
	return &Monitor{
		sourceTPacket: tpacket,
		parser:        newParser(config.QueryTypes),
		queryStats:    make(map[queryStatsKey]queryStatsValue),
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
	closeAllMetricChannels()
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
func (m *Monitor) processPacket(data []byte, packetCapturedAt time.Time) error {
	packet := Packet{
		capturedAt: packetCapturedAt,
	}
	if err := m.parser.parse(data, &packet); err != nil {
		return fmt.Errorf("parse a DNS packet: %s", err)
	}
	if err := m.recordQueryStats(packet); err != nil {
		return fmt.Errorf("record DNS statistics: %s", err)
	}
	return nil
}
