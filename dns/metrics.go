package dns

import (
	"context"

	nperfmetric "github.com/keisku/nperf/metric"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"golang.org/x/exp/slog"
)

// metrics
var (
	pollPacketEAGAIN        metric.Int64Counter           = noop.Int64Counter{}
	pollPacketTimeout       metric.Int64Counter           = noop.Int64Counter{}
	pollPacketError         metric.Int64Counter           = noop.Int64Counter{}
	parseDNSLayerSkip       metric.Int64Counter           = noop.Int64Counter{}
	parseIPLayerError       metric.Int64Counter           = noop.Int64Counter{}
	responseFailure         metric.Int64Counter           = noop.Int64Counter{}
	noCorrespondingResponse metric.Int64Counter           = noop.Int64Counter{}
	queryLatency            metric.Float64Histogram       = noop.Float64Histogram{}
	queryLatencyGauge       metric.Float64ObservableGauge = noop.Float64ObservableGauge{}
)

// channels to send datapoints
// Need to set the size of the channel to avoid blocking the sender.
// No intention of this number. Change it if we need.
var (
	queryLatencyGaugeCh    = make(chan nperfmetric.Datapoint[float64], 5)
	closeAllMetricChannels = func() {
		close(queryLatencyGaugeCh)
		slog.Debug("all metric channels are closed")
	}
)

func ConfigureMetricMeter(m metric.Meter) error {
	slog.Info("metric meter will be configured, then metrics will be recorded")

	var err error
	if pollPacketEAGAIN, err = m.Int64Counter("nperf_dns_poll_packet_eagain"); err != nil {
		return err
	}
	if pollPacketTimeout, err = m.Int64Counter("nperf_dns_poll_packet_timeout"); err != nil {
		return err
	}
	if pollPacketError, err = m.Int64Counter("nperf_dns_poll_packet_error"); err != nil {
		return err
	}
	if parseDNSLayerSkip, err = m.Int64Counter("nperf_dns_process_dns_layer_skip"); err != nil {
		return err
	}
	if parseIPLayerError, err = m.Int64Counter("nperf_dns_process_ip_layer_error"); err != nil {
		return err
	}
	if responseFailure, err = m.Int64Counter(
		"nperf_dns_response_failure",
		metric.WithDescription("A DNS response code is not successful."),
	); err != nil {
		return err
	}
	if noCorrespondingResponse, err = m.Int64Counter(
		"nperf_dns_no_corresponding_response",
		metric.WithDescription("No corresponding response for a DNS query. It means that we cannot record the latency of the DNS query."),
	); err != nil {
		return err
	}
	if queryLatency, err = m.Float64Histogram(
		"nperf_dns_query_latency",
		metric.WithDescription("The latency of a DNS query."),
		metric.WithUnit("ms"),
	); err != nil {
		return err
	}
	if queryLatencyGauge, err = m.Float64ObservableGauge(
		"dns_query_latency",
		metric.WithDescription("The latency of a DNS query."),
		metric.WithUnit("ms"),
	); err != nil {
		return err
	}
	if _, err = m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		for {
			select {
			case dp := <-queryLatencyGaugeCh:
				o.ObserveFloat64(queryLatencyGauge, dp.Value, metric.WithAttributes(dp.Attributes...))
			default:
				// To avoid blocking the callback.
				return nil
			}
		}
	}, queryLatencyGauge); err != nil {
		return err
	}
	return nil
}
