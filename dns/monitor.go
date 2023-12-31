package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/keisku/nperf/metric"
	"go.opentelemetry.io/otel/attribute"
)

// getNow is a variable for testing.
var getNow = time.Now

type Monitor struct {
	sourceTPacket *afpacket.TPacket
	parser        *parser
	queryStats    map[queryStatsKey]queryStatsValue
	answers       sync.Map // key: netip.Addr, value: Answer
	reverseCnames sync.Map // key: string (answer name), value: string (question name)
}

// answer represents a DNS answer.
type answer struct {
	Name      string     `json:"name"`
	IPAddr    netip.Addr `json:"ip_addr,omitempty"`
	ExpiredAt time.Time  `json:"expired_at"`
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

func NewMonitor() (*Monitor, error) {
	tpacket, err := newTPacket()
	if err != nil {
		return nil, fmt.Errorf("create raw socket: %s", err)
	}
	return &Monitor{
		sourceTPacket: tpacket,
		parser:        newParser(),
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
	deleteExpiredAnswerInterval := time.NewTicker(time.Minute)
	for {
		select {
		case <-ctx.Done():
			pollPacketInterval.Stop()
			deleteExpiredAnswerInterval.Stop()
			return
		case <-deleteExpiredAnswerInterval.C:
			// To prevent memory leak, delete expired answers.
			m.answers.Range(func(k, v any) bool {
				ipAddr := k.(netip.Addr)
				answer := v.(answer)
				if answer.ExpiredAt.Before(time.Now()) {
					m.deleteAnswer(ipAddr, answer.Name)
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
	m.storeAnswers(ctx, payload)
	if err := m.recordQueryStats(payload, packetCapturedAt); err != nil {
		return fmt.Errorf("record DNS statistics: %s", err)
	}
	return nil
}

// answerTTL is the time to live of an answer in the cache.
// We don't respect the original TTL of an answer because it is sometimes too short.
// We extend the TTL to 1 minute for reliable tags regarding domain names.
var answerTTL = time.Minute

func (m *Monitor) storeAnswers(ctx context.Context, payload Payload) {
	for _, ans := range payload.Answers {
		if ans.Type == layers.DNSTypeCNAME {
			m.reverseCnames.Store(string(ans.CNAME), string(ans.Name))
			continue
		}
		ipAddr, ok := netip.AddrFromSlice(ans.IP)
		if !ok {
			continue
		}
		m.answers.Store(ipAddr, answer{
			Name:      string(ans.Name),
			IPAddr:    ipAddr,
			ExpiredAt: getNow().Add(answerTTL),
		})
	}
}

func (m *Monitor) deleteAnswer(addr netip.Addr, name string) {
	m.answers.Delete(addr)
	for {
		slog.Debug("delete an expired dns cache")
		metric.Inc(metric.DNSExpiredCacheDelete, attribute.String("name", name), attribute.String("ip_addr", addr.String()))
		resolvedCname, ok := m.reverseCnames.LoadAndDelete(name)
		if !ok {
			break
		}
		name = resolvedCname.(string)
	}
}

// ReverseResolve resolves IP addresses to domain names and reverse CNAMEs.
func (m *Monitor) ReverseResolve(addrs []netip.Addr) (map[netip.Addr]string, map[string]string, error) {
	domains := make(map[netip.Addr]string, len(addrs))
	cnames := make(map[string]string, len(addrs))
	for _, addr := range addrs {
		v, ok := m.answers.Load(addr)
		if !ok {
			continue
		}
		answer := v.(answer)
		if answer.ExpiredAt.Before(getNow()) {
			m.deleteAnswer(addr, answer.Name)
			continue
		}
		name := answer.Name
		for {
			resolvedCname, ok := m.reverseCnames.Load(name)
			if !ok {
				break
			}
			cnames[name] = resolvedCname.(string)
			name = resolvedCname.(string)
		}
		domains[addr] = name
	}
	if len(domains) == 0 {
		return nil, nil, fmt.Errorf("domains associsted with the given addresses are not found: %v", addrs)
	}
	return domains, cnames, nil
}

type answerToDump struct {
	answer
	Cnames []string `json:"cnames"`
}

// DumpAnswers dumps all the dns record answers to the given writer.
func (m *Monitor) DumpAnswers(w io.Writer) error {
	var answers []answerToDump
	m.answers.Range(func(k, v any) bool {
		ipAddr := k.(netip.Addr)
		answer := v.(answer)
		if answer.ExpiredAt.Before(getNow()) {
			m.deleteAnswer(ipAddr, answer.Name)
			return true
		}
		var cnames []string
		for {
			resolvedCname, ok := m.reverseCnames.Load(answer.Name)
			if !ok {
				break
			}
			cnames = append(cnames, answer.Name)
			answer.Name = resolvedCname.(string)
		}
		answers = append(answers, answerToDump{
			answer: answer,
			Cnames: cnames,
		})
		return true
	})
	sort.Slice(answers, func(i, j int) bool {
		if answers[i].Name == answers[j].Name {
			return answers[i].IPAddr.String() < answers[j].IPAddr.String()
		}
		return answers[i].Name < answers[j].Name
	})
	data, err := json.MarshalIndent(answers, "", "    ")
	if err != nil {
		return fmt.Errorf("marshal answers: %s", err)
	}
	_, _ = w.Write(data)
	return nil
}
