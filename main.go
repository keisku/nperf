package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"
	"unicode"

	"github.com/cilium/ebpf/rlimit"
	"github.com/keisku/nperf/dns"
	nperfebpf "github.com/keisku/nperf/ebpf"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.20.0"
	"golang.org/x/exp/slog"
)

const version = "0.0.1"

type Options struct {
	Output       string
	OutputFormat string
	Port         int
}

func (o *Options) Validate() error {
	logWriter := os.Stdout
	if o.Output != "" {
		f, err := os.Create(o.Output)
		if err != nil {
			return err
		}
		logWriter = f
	}
	var logHandler slog.Handler
	logHandler = slog.NewJSONHandler(logWriter, nil)
	if strings.ToLower(o.OutputFormat) == "text" {
		logHandler = slog.NewTextHandler(logWriter, nil)
	}
	slog.SetDefault(slog.New(logHandler))
	return nil
}

// encoder writes metric data to stdout
type encoder struct{}

// TODO: This is a temporary implementation.
// - Support other metric types.
// - Support flitering by metric name.
// - Support other output locations.
// - Consider better output format.
func (encoder) Encode(v any) error {
	resourceMetrics, ok := v.(*metricdata.ResourceMetrics)
	if !ok {
		slog.Warn("failed to cast to metricdata.ResourceMetrics", slog.Any("value", v))
		return nil
	}
	for _, scopeMetric := range resourceMetrics.ScopeMetrics {
		for _, m := range scopeMetric.Metrics {
			switch v := m.Data.(type) {
			case metricdata.Gauge[int64]:
				for _, dp := range v.DataPoints {
					fmt.Printf("%s - %s | %d %s | %s | %v\n",
						m.Name,
						m.Description,
						dp.Value,
						m.Unit,
						dp.Time,
						getAttrs(dp.Attributes),
					)
				}
			}
		}
	}
	return nil
}

func getAttrs(attrs attribute.Set) map[string][]string {
	keysMap := make(map[string][]string)
	itr := attrs.Iter()
	for itr.Next() {
		kv := itr.Attribute()
		key := strings.Map(sanitizeRune, string(kv.Key))
		if _, ok := keysMap[key]; !ok {
			keysMap[key] = []string{kv.Value.Emit()}
		} else {
			// if the sanitized key is a duplicate, append to the list of keys
			keysMap[key] = append(keysMap[key], kv.Value.Emit())
		}
	}
	return keysMap
}

func sanitizeRune(r rune) rune {
	if unicode.IsLetter(r) || unicode.IsDigit(r) || r == ':' || r == '_' {
		return r
	}
	return '_'
}

func initMeterProvider() (func(context.Context) error, error) {
	stdoutExporter, err := stdoutmetric.New(stdoutmetric.WithEncoder(encoder{}))
	if err != nil {
		return nil, fmt.Errorf("create stdout exporter: %s", err)
	}
	reader, err := otelprom.New()
	if err != nil {
		return nil, fmt.Errorf("create prometheus reader: %s", err)
	}
	meterProvider := metric.NewMeterProvider(
		metric.WithReader(reader),
		metric.WithReader(metric.NewPeriodicReader(stdoutExporter, metric.WithInterval(time.Second))),
		metric.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("nperf"),
		)),
	)
	otel.SetMeterProvider(meterProvider)
	return meterProvider.Shutdown, nil
}

func (o *Options) Run(ctx context.Context) error {
	stopebpf, err := nperfebpf.Start()
	if err != nil {
		return fmt.Errorf("failed to start ebpf programs: %s", err)
	}
	shutdownMeterProvider, err := initMeterProvider()
	if err != nil {
		return fmt.Errorf("failed to create meter provider: %s", err)
	}

	// DNS
	dnsMonitor, err := dns.NewMonitor(dns.Config{})
	if err != nil {
		return fmt.Errorf("failed to create DNS Monitor: %s", err)
	}
	if err := dns.ConfigureMetricMeter(otel.GetMeterProvider().Meter(
		"nperf.dns",
		otelmetric.WithInstrumentationVersion(version),
	)); err != nil {
		return fmt.Errorf("failed to set metric meter of dns: %s", err)
	}
	go dnsMonitor.Run(ctx)

	// HTTP server
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	go func() {
		err := http.ListenAndServe(fmt.Sprintf(":%d", o.Port), mux)
		if err != nil {
			slog.Warn("failed to start prometheus server", slog.Any("error", err))
		}
	}()

	<-ctx.Done()
	slog.Info("exiting nperf...")
	stopCh := make(chan struct{})
	go func() {
		if err := shutdownMeterProvider(context.Background()); err != nil {
			slog.Warn("failed to shutdown meter provider", slog.Any("error", err))
		}
		stopebpf()
		close(stopCh)
	}()
	select {
	case <-stopCh:
		slog.Info("nperf shutdown gracefully")
	case <-time.After(5 * time.Second):
		slog.Error("failed to shutdown gracefully, force exiting...")
	}
	return nil
}

func NewCmd() *cobra.Command {
	o := &Options{
		Output:       "",
		OutputFormat: "json",
		Port:         7000,
	}
	cmd := &cobra.Command{
		Use:          "ntop",
		SilenceUsage: true,
	}
	cmd.Flags().StringVarP(&o.Output, "output", "o", o.Output, "write output to this file instead of stdout")
	cmd.Flags().StringVar(&o.OutputFormat, "output-format", o.OutputFormat, "write output in this format")
	cmd.Flags().IntVarP(&o.Port, "port", "p", o.Port, "port to listen on")
	cmd.RunE = func(c *cobra.Command, _ []string) error {
		if err := o.Validate(); err != nil {
			return err
		}
		return o.Run(c.Context())
	}
	return cmd
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	errlog := log.New(os.Stderr, "", log.LstdFlags)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		errlog.Println(err)
	}

	if err := NewCmd().ExecuteContext(ctx); err != nil {
		errlog.Println(err)
	}
}
