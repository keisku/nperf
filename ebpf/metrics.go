package ebpf

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"golang.org/x/exp/slog"
)

var (
	tcpSentBytes      metric.Float64ObservableGauge = noop.Float64ObservableGauge{}
	tcpRecvBytes      metric.Float64ObservableGauge = noop.Float64ObservableGauge{}
	tcpSentPackets    metric.Int64ObservableGauge   = noop.Int64ObservableGauge{}
	tcpRecvPackets    metric.Int64ObservableGauge   = noop.Int64ObservableGauge{}
	tcpRtt            metric.Float64ObservableGauge = noop.Float64ObservableGauge{}
	tcpRttHistgram    metric.Float64Histogram       = noop.Float64Histogram{}
	tcpRttVar         metric.Float64ObservableGauge = noop.Float64ObservableGauge{}
	tcpRttVarHistgram metric.Float64Histogram       = noop.Float64Histogram{}
)

var (
	tcpSentBytesCh   = make(chan datapoint[float64], 100)
	tcpRecvBytesCh   = make(chan datapoint[float64], 100)
	tcpSentPacketsCh = make(chan datapoint[int64], 100)
	tcpRecvPacketsCh = make(chan datapoint[int64], 100)
	tcpRttCh         = make(chan datapoint[float64], 100)
	tcpRttVarCh      = make(chan datapoint[float64], 100)
)

func ConfigureMetricMeter(m metric.Meter) error {
	const (
		tcpRttName = "nperf_tcp_rtt"
		tcpRttDesc = `Smoothed Round Trip Time is the exponentially weighted moving average of RTT samples,
reflecting the average time for a packet's round trip in a TCP connection. 
It's vital for TCP algorithms, particularly the retransmission timeout (RTO) calculation.`
		tcpRttVarName = "nperf_tcp_mean_deviation_rtt"
		tcpRttVarDesc = `The variability or fluctuation in the RTT samples.
The mean deviation is used in conjunction with the smoothed RTT to calculate the RTO.
A higher mean deviation indicates that the RTT samples are more variable.`
	)

	var err error
	if tcpSentBytes, err = m.Float64ObservableGauge(
		"nperf_tcp_sent_bytes",
		metric.WithDescription("The number of bytes sent."),
		metric.WithUnit("kb"),
	); err != nil {
		return err
	}
	if err = registerFloat64(m, tcpSentBytesCh, tcpSentBytes); err != nil {
		return err
	}
	if tcpRecvBytes, err = m.Float64ObservableGauge(
		"nperf_tcp_recv_bytes",
		metric.WithDescription("The number of bytes received."),
		metric.WithUnit("kb"),
	); err != nil {
		return err
	}
	if err = registerFloat64(m, tcpRecvBytesCh, tcpRecvBytes); err != nil {
		return err
	}
	if tcpSentPackets, err = m.Int64ObservableGauge(
		"nperf_tcp_sent_packets",
		metric.WithDescription("The number of packets sent."),
	); err != nil {
		return err
	}
	if err = registerInt64(m, tcpSentPacketsCh, tcpSentPackets); err != nil {
		return err
	}
	if tcpRecvPackets, err = m.Int64ObservableGauge(
		"nperf_tcp_recv_packets",
		metric.WithDescription("The number of packets received."),
	); err != nil {
		return err
	}
	if err = registerInt64(m, tcpRecvPacketsCh, tcpRecvPackets); err != nil {
		return err
	}
	if tcpRtt, err = m.Float64ObservableGauge(
		tcpRttName,
		metric.WithDescription(tcpRttDesc),
		metric.WithUnit("ms"),
	); err != nil {
		return err
	}
	if err = registerFloat64(m, tcpRttCh, tcpRtt); err != nil {
		return err
	}
	if tcpRttHistgram, err = m.Float64Histogram(
		tcpRttName,
		metric.WithDescription(tcpRttDesc),
	); err != nil {
		return err
	}
	if tcpRttVar, err = m.Float64ObservableGauge(
		tcpRttVarName,
		metric.WithDescription(tcpRttVarDesc),
		metric.WithUnit("ms"),
	); err != nil {
		return err
	}
	if err = registerFloat64(m, tcpRttVarCh, tcpRttVar); err != nil {
		return err
	}
	if tcpRttVarHistgram, err = m.Float64Histogram(
		tcpRttVarName,
		metric.WithDescription(tcpRttVarDesc),
	); err != nil {
		return err
	}
	return nil
}

func registerFloat64(m metric.Meter, ch chan datapoint[float64], obs metric.Float64ObservableGauge) error {
	_, err := m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		for {
			select {
			case dp := <-ch:
				o.ObserveFloat64(obs, dp.value, metric.WithAttributes(dp.attributes...))
			default:
				// To avoid blocking the callback.
				return nil
			}
		}
	}, obs)
	return err
}

func registerInt64(m metric.Meter, ch chan datapoint[int64], obs metric.Int64ObservableGauge) error {
	_, err := m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		for {
			select {
			case dp := <-ch:
				o.ObserveInt64(obs, dp.value, metric.WithAttributes(dp.attributes...))
			default:
				// To avoid blocking the callback.
				return nil
			}
		}
	}, obs)
	return err
}

type datapoint[N int64 | float64] struct {
	value      N
	attributes []attribute.KeyValue
}

func sendDatapoint[N int64 | float64](ch chan<- datapoint[N], dp datapoint[N]) {
	select {
	case ch <- dp:
	default:
		slog.Warn("can't send a datapoint")
	}
}
