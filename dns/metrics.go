package dns

import (
	"fmt"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

var (
	meter metric.Meter = noop.Meter{}

	metricPrefix = "nmon_dns_"
	metricName   = func(prefix, name string) string {
		return fmt.Sprintf("%s%s", prefix, name)
	}

	metricPrefixPollPacket = fmt.Sprintf("%spoll_packet_", metricPrefix)
	pollPacketEAGAIN       metric.Int64Counter
	pollPacketTimeout      metric.Int64Counter
	pollPacketErr          metric.Int64Counter

	metricPrefixParseDNSLayer = fmt.Sprintf("%sparse_dns_layer_", metricPrefix)
	parseDNSLayerErr          metric.Int64Counter

	metricPrefixParseIPLayer = fmt.Sprintf("%sparse_ip_layer_", metricPrefix)
	parseIPLayerErr          metric.Int64Counter
)

func ConfigureMetricMeter(m metric.Meter) error {
	meter = m

	var err error
	if err != nil {
		return err
	}
	pollPacketEAGAIN, err = meter.Int64Counter(metricName(metricPrefixPollPacket, "eagain"))
	if err != nil {
		return err
	}
	pollPacketTimeout, err = meter.Int64Counter(metricName(metricPrefixPollPacket, "timeout"))
	if err != nil {
		return err
	}
	pollPacketErr, err = meter.Int64Counter(metricName(metricPrefixPollPacket, "error"))
	if err != nil {
		return err
	}
	parseDNSLayerErr, err = meter.Int64Counter(metricName(metricPrefixParseDNSLayer, "error"))
	if err != nil {
		return err
	}
	parseIPLayerErr, err = meter.Int64Counter(metricName(metricPrefixParseIPLayer, "error"))
	if err != nil {
		return err
	}
	return nil
}
