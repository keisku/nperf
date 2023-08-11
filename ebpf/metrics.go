package ebpf

import (
	nperfmetric "github.com/keisku/nperf/metric"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
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

const datapointChannelSize = 100

var (
	tcpSentBytesCh   = make(chan nperfmetric.Datapoint[float64], datapointChannelSize)
	tcpRecvBytesCh   = make(chan nperfmetric.Datapoint[float64], datapointChannelSize)
	tcpSentPacketsCh = make(chan nperfmetric.Datapoint[int64], datapointChannelSize)
	tcpRecvPacketsCh = make(chan nperfmetric.Datapoint[int64], datapointChannelSize)
	tcpRttCh         = make(chan nperfmetric.Datapoint[float64], datapointChannelSize)
	tcpRttVarCh      = make(chan nperfmetric.Datapoint[float64], datapointChannelSize)
)

func ConfigureMetricMeter(m metric.Meter) error {
	const (
		tcpRttDesc = `Smoothed Round Trip Time is the exponentially weighted moving average of RTT samples,
reflecting the average time for a packet's round trip in a TCP connection. 
It's vital for TCP algorithms, particularly the retransmission timeout (RTO) calculation.`
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
	if err = nperfmetric.RegisterFloat64(m, tcpSentBytesCh, tcpSentBytes); err != nil {
		return err
	}
	if tcpRecvBytes, err = m.Float64ObservableGauge(
		"nperf_tcp_recv_bytes",
		metric.WithDescription("The number of bytes received."),
		metric.WithUnit("kb"),
	); err != nil {
		return err
	}
	if err = nperfmetric.RegisterFloat64(m, tcpRecvBytesCh, tcpRecvBytes); err != nil {
		return err
	}
	if tcpSentPackets, err = m.Int64ObservableGauge(
		"nperf_tcp_sent_packets",
		metric.WithDescription("The number of packets sent."),
	); err != nil {
		return err
	}
	if err = nperfmetric.RegisterInt64(m, tcpSentPacketsCh, tcpSentPackets); err != nil {
		return err
	}
	if tcpRecvPackets, err = m.Int64ObservableGauge(
		"nperf_tcp_recv_packets",
		metric.WithDescription("The number of packets received."),
	); err != nil {
		return err
	}
	if err = nperfmetric.RegisterInt64(m, tcpRecvPacketsCh, tcpRecvPackets); err != nil {
		return err
	}
	if tcpRtt, err = m.Float64ObservableGauge(
		"tcp_rtt",
		metric.WithDescription(tcpRttDesc),
		metric.WithUnit("ms"),
	); err != nil {
		return err
	}
	if err = nperfmetric.RegisterFloat64(m, tcpRttCh, tcpRtt); err != nil {
		return err
	}
	if tcpRttHistgram, err = m.Float64Histogram(
		"nperf_tcp_rtt",
		metric.WithDescription(tcpRttDesc),
	); err != nil {
		return err
	}
	if tcpRttVar, err = m.Float64ObservableGauge(
		"tcp_mean_deviation_rtt",
		metric.WithDescription(tcpRttVarDesc),
		metric.WithUnit("ms"),
	); err != nil {
		return err
	}
	if err = nperfmetric.RegisterFloat64(m, tcpRttVarCh, tcpRttVar); err != nil {
		return err
	}
	if tcpRttVarHistgram, err = m.Float64Histogram(
		"nperf_tcp_mean_deviation_rtt",
		metric.WithDescription(tcpRttVarDesc),
	); err != nil {
		return err
	}
	return nil
}
