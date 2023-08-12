package metric

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"golang.org/x/exp/slog"
)

const PollInerval = 100 * time.Millisecond

type Name uint16

const (
	Unknown Name = iota

	// DNS
	DNSPollPacketEAGAIN
	DNSPollPacketTimeout
	DNSPollPacketError
	DNSParseDNSLayerSkip
	DNSParseIPLayerError
	DNSResponseFailure
	DNSNoCorrespondingResponse
	DNSQueryLatency
	DNSDiscardQuestion

	// TCP
	TCPSentBytes
	TCPRecvBytes
	TCPSentPackets
	TCPRecvPackets
	TCPRtt
	TCPRttVar
	TCPRetransmits
)

func (n Name) String() string {
	return [...]string{
		"unknown",
		"nperf_dns_poll_packet_eagain",
		"nperf_dns_poll_packet_timeout",
		"nperf_dns_poll_packet_error",
		"nperf_dns_parse_dns_layer_skip",
		"nperf_dns_parse_ip_layer_error",
		"nperf_dns_response_failure",
		"nperf_dns_no_corresponding_response",
		"nperf_dns_query_latency",
		"nperf_dns_discard_question",
		"nperf_tcp_sent_bytes",
		"nperf_tcp_recv_bytes",
		"nperf_tcp_sent_packets",
		"nperf_tcp_recv_packets",
		"nperf_tcp_rtt",
		"nperf_tcp_mean_deviation_rtt",
		"nperf_tcp_retransmits",
	}[n]
}

func (n Name) instrumentOptions() [2]metric.InstrumentOption {
	var instrumentOptions = map[Name][2]metric.InstrumentOption{
		DNSPollPacketEAGAIN:        {metric.WithUnit(""), metric.WithDescription("")},
		DNSPollPacketTimeout:       {metric.WithUnit(""), metric.WithDescription("")},
		DNSPollPacketError:         {metric.WithUnit(""), metric.WithDescription("")},
		DNSParseDNSLayerSkip:       {metric.WithUnit(""), metric.WithDescription("")},
		DNSParseIPLayerError:       {metric.WithUnit(""), metric.WithDescription("")},
		DNSResponseFailure:         {metric.WithUnit(""), metric.WithDescription("A DNS response code is not successful.")},
		DNSNoCorrespondingResponse: {metric.WithUnit(""), metric.WithDescription("No corresponding response for a DNS query. It means that we cannot record the latency of the DNS query.")},
		DNSQueryLatency:            {metric.WithUnit("ms"), metric.WithDescription("The latency of a DNS query.")},
		DNSDiscardQuestion:         {metric.WithUnit(""), metric.WithDescription("Discard a DNS question.")},
		TCPSentBytes:               {metric.WithUnit("kb"), metric.WithDescription("The number of kilobytes sent.")},
		TCPRecvBytes:               {metric.WithUnit("kb"), metric.WithDescription("The number of kilobytes received.")},
		TCPSentPackets:             {metric.WithUnit("packets"), metric.WithDescription("The number of packets sent.")},
		TCPRecvPackets:             {metric.WithUnit("packets"), metric.WithDescription("The number of packets received.")},
		TCPRtt: {metric.WithUnit("ms"), metric.WithDescription(`Smoothed Round Trip Time is the exponentially weighted moving average of RTT samples,
reflecting the average time for a packet's round trip in a TCP connection. 
It's vital for TCP algorithms, particularly the retransmission timeout (RTO) calculation.`)},
		TCPRttVar: {metric.WithUnit("ms"), metric.WithDescription(`The variability or fluctuation in the RTT samples.
The mean deviation is used in conjunction with the smoothed RTT to calculate the RTO.
A higher mean deviation indicates that the RTT samples are more variable.`)},
		TCPRetransmits: {metric.WithUnit("packets"), metric.WithDescription(`The number of TCP packets retransmitted.`)},
	}
	return instrumentOptions[n]
}

var (
	dnsPollPacketEAGAIN        metric.Int64Counter           = noop.Int64Counter{}
	dnsPollPacketTimeout       metric.Int64Counter           = noop.Int64Counter{}
	dnsPollPacketError         metric.Int64Counter           = noop.Int64Counter{}
	dnsParseDNSLayerSkip       metric.Int64Counter           = noop.Int64Counter{}
	dnsParseIPLayerError       metric.Int64Counter           = noop.Int64Counter{}
	dnsResponseFailure         metric.Int64Counter           = noop.Int64Counter{}
	dnsNoCorrespondingResponse metric.Int64Counter           = noop.Int64Counter{}
	dnsQueryLatency            metric.Float64ObservableGauge = noop.Float64ObservableGauge{}
	dnsDiscardQuestion         metric.Int64Counter           = noop.Int64Counter{}
	tcpSentBytes               metric.Float64ObservableGauge = noop.Float64ObservableGauge{}
	tcpRecvBytes               metric.Float64ObservableGauge = noop.Float64ObservableGauge{}
	tcpSentPackets             metric.Float64ObservableGauge = noop.Float64ObservableGauge{}
	tcpRecvPackets             metric.Float64ObservableGauge = noop.Float64ObservableGauge{}
	tcpRtt                     metric.Float64ObservableGauge = noop.Float64ObservableGauge{}
	tcpRttVar                  metric.Float64ObservableGauge = noop.Float64ObservableGauge{}
	tcpRetransmits             metric.Float64ObservableGauge = noop.Float64ObservableGauge{}
)

var int64CounterMetrics = map[Name]metric.Int64Counter{
	DNSPollPacketEAGAIN:        dnsPollPacketEAGAIN,
	DNSPollPacketTimeout:       dnsPollPacketTimeout,
	DNSPollPacketError:         dnsPollPacketError,
	DNSParseDNSLayerSkip:       dnsParseDNSLayerSkip,
	DNSParseIPLayerError:       dnsParseIPLayerError,
	DNSResponseFailure:         dnsResponseFailure,
	DNSNoCorrespondingResponse: dnsNoCorrespondingResponse,
	DNSDiscardQuestion:         dnsDiscardQuestion,
}

var float64ObservableGaugeMetrics = map[Name]metric.Float64ObservableGauge{
	DNSQueryLatency: dnsQueryLatency,
	TCPSentBytes:    tcpSentBytes,
	TCPRecvBytes:    tcpRecvBytes,
	TCPSentPackets:  tcpSentPackets,
	TCPRecvPackets:  tcpRecvPackets,
	TCPRtt:          tcpRtt,
	TCPRttVar:       tcpRttVar,
	TCPRetransmits:  tcpRetransmits,
}

type datapoint[N int64 | float64] struct {
	Name       Name
	Value      N
	Attributes []attribute.KeyValue
}

const (
	dnsChannelSize = 10
	tcpChannelSize = 100
)

var (
	float64ObservableGaugeCh = map[Name]chan datapoint[float64]{
		DNSQueryLatency: make(chan datapoint[float64], dnsChannelSize),
		TCPSentBytes:    make(chan datapoint[float64], tcpChannelSize),
		TCPRecvBytes:    make(chan datapoint[float64], tcpChannelSize),
		TCPSentPackets:  make(chan datapoint[float64], tcpChannelSize),
		TCPRecvPackets:  make(chan datapoint[float64], tcpChannelSize),
		TCPRtt:          make(chan datapoint[float64], tcpChannelSize),
		TCPRttVar:       make(chan datapoint[float64], tcpChannelSize),
		TCPRetransmits:  make(chan datapoint[float64], tcpChannelSize),
	}
	once     sync.Once
	closeChs = func() {
		once.Do(func() {
			for name := range float64ObservableGaugeCh {
				close(float64ObservableGaugeCh[name])
			}
		})
	}
)

func ConfigureMetricMeter(m metric.Meter) (func(), error) {
	var err error
	for name := range int64CounterMetrics {
		if int64CounterMetrics[name], err = m.Int64Counter(
			name.String(),
			name.instrumentOptions()[0],
			name.instrumentOptions()[1],
		); err != nil {
			return closeChs, err
		}
	}
	for name := range float64ObservableGaugeMetrics {
		// Using an anonymous function to capture the current value of `name`` in each iteration.
		// Without this, all callbacks would reference the first value of 'name' from the loop.
		err := func(name Name) error {
			gauge, err := m.Float64ObservableGauge(
				name.String(),
				name.instrumentOptions()[0],
				name.instrumentOptions()[1],
			)
			if err != nil {
				return err
			}
			float64ObservableGaugeMetrics[name] = gauge
			if _, err = m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
				for {
					select {
					case dp := <-float64ObservableGaugeCh[name]:
						o.ObserveFloat64(gauge, dp.Value, metric.WithAttributes(dp.Attributes...))
					default:
						// To avoid blocking the callback.
						return nil
					}
				}
			}, gauge); err != nil {
				return err
			}
			return nil
		}(name)
		if err != nil {
			return closeChs, err
		}
	}
	return closeChs, nil
}

func Inc(name Name, attrs ...attribute.KeyValue) {
	switch name {
	case Unknown:
		slog.Warn("The datapoint is dropped because the name is unknown")
	default:
		if c, ok := int64CounterMetrics[name]; ok {
			c.Add(context.Background(), 1, metric.WithAttributes(attrs...))
		} else {
			slog.Warn("The datapoint is dropped because the name is not found")
		}
	}
}

func Gauge(name Name, value float64, attrs ...attribute.KeyValue) {
	switch name {
	case Unknown:
		slog.Warn("The datapoint is dropped because the name is unknown")
	default:
		if ch, ok := float64ObservableGaugeCh[name]; ok {
			select {
			case ch <- datapoint[float64]{Name: name, Value: value, Attributes: attrs}:
			default:
				slog.Warn("The datapoint is dropped because the channel is full")
			}
		} else {
			slog.Warn("The datapoint is dropped because the name is not found")
		}
	}
}
