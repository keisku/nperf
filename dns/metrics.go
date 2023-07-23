package dns

import (
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

var (
	meter metric.Meter = noop.Meter{}

	pollPacketEAGAIN        metric.Int64Counter   = noop.Int64Counter{}
	pollPacketTimeout       metric.Int64Counter   = noop.Int64Counter{}
	pollPacketError         metric.Int64Counter   = noop.Int64Counter{}
	parseDNSLayerError      metric.Int64Counter   = noop.Int64Counter{}
	parseIPLayerError       metric.Int64Counter   = noop.Int64Counter{}
	responseFailure         metric.Int64Counter   = noop.Int64Counter{}
	noCorrespondingResponse metric.Int64Counter   = noop.Int64Counter{}
	queryLatency            metric.Int64Histogram = noop.Int64Histogram{}
)

// ConfigureMetricMeter configures the metric meter to be used by the dns package.
func ConfigureMetricMeter(m metric.Meter) error {
	meter = m

	var err error
	if pollPacketEAGAIN, err = meter.Int64Counter("nmon_dns_poll_packet_eagain"); err != nil {
		return err
	}
	if pollPacketTimeout, err = meter.Int64Counter("nmon_dns_poll_packet_timeout"); err != nil {
		return err
	}
	if pollPacketError, err = meter.Int64Counter("nmon_dns_poll_packet_error"); err != nil {
		return err
	}
	if parseDNSLayerError, err = meter.Int64Counter("nmon_dns_process_dns_layer_error"); err != nil {
		return err
	}
	if parseIPLayerError, err = meter.Int64Counter("nmon_dns_process_ip_layer_error"); err != nil {
		return err
	}
	if responseFailure, err = meter.Int64Counter(
		"nmon_dns_response_failure",
		metric.WithDescription("A DNS response code is not successful."),
	); err != nil {
		return err
	}
	if noCorrespondingResponse, err = meter.Int64Counter(
		"nmon_dns_no_corresponding_response",
		metric.WithDescription("No corresponding response for a DNS query. It means that we cannot record the latency of the DNS query."),
	); err != nil {
		return err
	}
	if queryLatency, err = meter.Int64Histogram(
		"nmon_dns_query_latency",
		metric.WithDescription("The latency of a DNS query."),
		metric.WithUnit("microseconds"),
	); err != nil {
		return err
	}
	return nil
}
