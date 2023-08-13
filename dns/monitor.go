package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/keisku/nperf/metric"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/exp/slog"
)

// getNow is a variable for testing.
var getNow = time.Now

type Monitor struct {
	sourceTPacket *afpacket.TPacket
	parser        *parser
	queryStats    map[queryStatsKey]queryStatsValue
	answers       sync.Map // key: netip.Addr, value: Answer
}

// Answer represents a DNS answer.
type Answer struct {
	Name      string        `json:"name"`
	IPAddrs   []netip.Addr  `json:"ip_addrs"`
	TTL       time.Duration `json:"ttl"`
	ExpiredAt time.Time     `json:"expired_at"`
}

type queryStatsKey struct {
	connection    Connection
	transactionId uint16
}

type queryStatsValue struct {
	packetCapturedAt time.Time
	question         layers.DNSQuestion
}

func convertDNSQuestionToAttributes(question layers.DNSQuestion) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("question", string(question.Name)),
		attribute.String("query_type", question.Type.String()),
		attribute.String("query_class", question.Class.String()),
	}
}

func (v queryStatsValue) Attributes() []attribute.KeyValue {
	// Don't add the packetCapturedAt to the attributes because it's high cardinality.
	return convertDNSQuestionToAttributes(v.question)
}

func (m *Monitor) recordQueryStats(payload Payload, capturedAt time.Time) error {
	queryStatsKey := queryStatsKey{
		connection:    payload.connection,
		transactionId: payload.ID,
	}
	var question layers.DNSQuestion
	if 1 <= len(payload.Questions) {
		question = payload.Questions[0]
		if 0 < len(payload.Questions[1:]) {
			slog.Warn("discard the second and subsequent questions", slog.Any("discard_questions", payload.Questions[1:]))
			for _, q := range payload.Questions[1:] {
				metric.Inc(metric.DNSDiscardQuestion, append(payload.Attributes(), convertDNSQuestionToAttributes(q)...)...)
			}
		}
	}
	if !payload.QR {
		if _, ok := m.queryStats[queryStatsKey]; !ok {
			if 1 <= len(payload.Questions) {
				m.queryStats[queryStatsKey] = queryStatsValue{
					packetCapturedAt: capturedAt,
					question:         question,
				}
			}
		}
		return nil
	}
	queryStats, ok := m.queryStats[queryStatsKey]
	if !ok {
		metric.Inc(metric.DNSNoCorrespondingResponse, append(payload.Attributes(), convertDNSQuestionToAttributes(question)...)...)
		return fmt.Errorf("no corresponding query entry for a response: %#v", payload.connection)
	}

	metricAttrs := append(queryStats.Attributes(), payload.Attributes()...)

	delete(m.queryStats, queryStatsKey)

	latency := float64(capturedAt.Sub(queryStats.packetCapturedAt)) / float64(time.Millisecond)
	metric.Gauge(metric.DNSQueryLatency, latency, metricAttrs...)
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
	m.pollPackets(ctx) // blocking until the context is canceled
	slog.Info("stop polling packets")
	m.sourceTPacket.Close()
}

// pollPackets polls for incoming packets and processes them.
// It blocks until the context is canceled.
func (m *Monitor) pollPackets(ctx context.Context) {
	pollPacketInterval := time.NewTicker(5 * time.Millisecond)
	clearExpiredAnswerInterval := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case <-clearExpiredAnswerInterval.C:
			// To prevent memory leak, delete expired answers.
			m.answers.Range(func(k, v any) bool {
				answer, ok := v.(Answer)
				if !ok {
					slog.Warn("delete an unexpected type of answer", attribute.String("type", fmt.Sprintf("%T", v)))
					m.answers.Delete(k)
					return true
				}
				if answer.ExpiredAt.Before(time.Now()) {
					m.answers.Delete(k)
				}
				return true
			})
		case <-pollPacketInterval.C:
			data, captureInfo, err := m.sourceTPacket.ZeroCopyReadPacketData()

			// This is the error code returned when an operation on a non-blocking socket cannot be completed immediately.
			// It tells the program that the operation would have caused the process to be suspended,
			// and the process should try the operation again later.
			if err == syscall.EAGAIN {
				metric.Inc(metric.DNSPollPacketEAGAIN)
				continue
			}
			if err == afpacket.ErrTimeout {
				metric.Inc(metric.DNSPollPacketTimeout)
				slog.Debug("timeout while reading a packet")
				continue
			}
			if err != nil {
				metric.Inc(metric.DNSPollPacketError, attribute.String("error", err.Error()))
				slog.Warn("read a packet", err)
				continue
			}

			if err := m.processPacket(ctx, data, captureInfo.Timestamp); err != nil {
				slog.Debug(fmt.Sprintf("retrieve DNS information form a received packet: %s", err))
			}
		}
	}
}

// processPacket retrieves DNS information from the received packet data.
func (m *Monitor) processPacket(ctx context.Context, data []byte, packetCapturedAt time.Time) error {
	var payload Payload
	if err := m.parser.parse(data, &payload); err != nil {
		return fmt.Errorf("parse a DNS packet: %s", err)
	}
	m.storeDomains(ctx, payload)
	if err := m.recordQueryStats(payload, packetCapturedAt); err != nil {
		return fmt.Errorf("record DNS statistics: %s", err)
	}
	return nil
}

func (m *Monitor) storeDomains(ctx context.Context, payload Payload) {
	for _, ans := range payload.Answers {
		ipAddr, ok := netip.AddrFromSlice(ans.IP)
		if !ok {
			continue
		}
		ttl := time.Duration(ans.TTL) * time.Second
		m.answers.Store(ipAddr, Answer{
			Name:      string(ans.Name),
			IPAddrs:   []netip.Addr{ipAddr},
			TTL:       ttl,
			ExpiredAt: getNow().Add(ttl),
		})
	}
}

// ReverseResolve returns a map of IP addresses to domain names.
func (m *Monitor) ReverseResolve(addrs []netip.Addr) (map[netip.Addr]string, error) {
	domains := make(map[netip.Addr]string, len(addrs))
	for _, addr := range addrs {
		v, ok := m.answers.Load(addr)
		if !ok {
			continue
		}
		answer, ok := v.(Answer)
		if !ok {
			slog.Warn("delete an unexpected type of answer", attribute.String("type", fmt.Sprintf("%T", v)))
			m.answers.Delete(addr)
			continue
		}
		if answer.ExpiredAt.Before(time.Now()) {
			slog.Debug("delete an expired resolved answer",
				attribute.String("name", answer.Name),
				attribute.String("ip_addr", addr.String()),
				attribute.String("expired_at", answer.ExpiredAt.String()))
			m.answers.Delete(addr)
			continue
		}
		domains[addr] = answer.Name

	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("domains associsted with the given addresses are not found: %v", addrs)
	}
	return domains, nil
}

func mergeAnswers(answers []Answer) []Answer {
	mergedMap := make(map[string]Answer)
	for _, answer := range answers {
		if existing, ok := mergedMap[answer.Name]; ok {
			// Merging IP addresses and ensuring uniqueness
			existingSet := make(map[string]bool)
			for _, ip := range existing.IPAddrs {
				existingSet[ip.String()] = true
			}
			for _, ip := range answer.IPAddrs {
				if !existingSet[ip.String()] {
					existing.IPAddrs = append(existing.IPAddrs, ip)
				}
			}
			sort.Slice(existing.IPAddrs, func(i, j int) bool {
				return existing.IPAddrs[i].String() < existing.IPAddrs[j].String()
			})
			mergedMap[answer.Name] = existing
		} else {
			mergedMap[answer.Name] = answer
		}
	}

	// Convert the map to a slice
	merged := make([]Answer, 0, len(mergedMap))
	for _, answer := range mergedMap {
		merged = append(merged, answer)
	}
	sort.Slice(merged, func(i, j int) bool {
		return merged[i].Name < merged[j].Name
	})
	return merged
}

// DumpAnswers dumps all the dns record answers to the given writer.
func (m *Monitor) DumpAnswers(w io.Writer) error {
	var answers []Answer
	m.answers.Range(func(k, v any) bool {
		ipAddr, ok := k.(netip.Addr)
		if !ok {
			slog.Warn("delete an unexpected type of key", attribute.String("type", fmt.Sprintf("%T", k)))
			m.answers.Delete(k)
			return true
		}
		answer, ok := v.(Answer)
		if !ok {
			slog.Warn("delete an unexpected type of answer", attribute.String("type", fmt.Sprintf("%T", v)))
			m.answers.Delete(k)
			return true
		}
		if answer.ExpiredAt.Before(getNow()) {
			slog.Debug("delete an expired resolved answer",
				attribute.String("name", answer.Name),
				attribute.String("ip_addr", ipAddr.String()),
				attribute.String("expired_at", answer.ExpiredAt.String()))
			m.answers.Delete(k)
			return true
		}
		answers = append(answers, answer)
		return true
	})
	answersToDump := mergeAnswers(answers)
	data, err := json.MarshalIndent(answersToDump, "", "    ")
	if err != nil {
		return fmt.Errorf("marshal answers: %s", err)
	}
	_, _ = w.Write(data)
	return nil
}
