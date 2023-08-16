package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/keisku/nperf/dns"
	nperfebpf "github.com/keisku/nperf/ebpf"
	nperfmetric "github.com/keisku/nperf/metric"
	"github.com/keisku/nperf/process"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/sdk/metric"
)

type Options struct {
	LogLevel          string
	Output            string
	OutputFormat      string
	Port              int
	DisableDNS        bool
	DisableeBPF       bool
	IncludeNames      []string
	ExcludeNames      []string
	IncludeAttributes []string
	ExcludeAttributes []string
}

func (o *Options) Validate() error {
	var logLevel = new(slog.LevelVar)
	logHandlerOpts := &slog.HandlerOptions{Level: logLevel}
	switch strings.ToUpper(o.LogLevel) {
	case slog.LevelDebug.String():
		logLevel.Set(slog.LevelDebug)
	case slog.LevelInfo.String():
		logLevel.Set(slog.LevelInfo)
	case slog.LevelWarn.String():
		logLevel.Set(slog.LevelWarn)
	case slog.LevelError.String():
		logLevel.Set(slog.LevelError)
	default:
		logLevel.Set(slog.LevelInfo)
	}
	logWriter := os.Stdout
	if o.Output != "" {
		f, err := os.Create(o.Output)
		if err != nil {
			return err
		}
		logWriter = f
	}
	var logHandler slog.Handler
	logHandler = slog.NewJSONHandler(logWriter, logHandlerOpts)
	if strings.ToLower(o.OutputFormat) == "text" {
		logHandler = slog.NewTextHandler(logWriter, logHandlerOpts)
	}
	slog.SetDefault(slog.New(logHandler))
	return nil
}

func initMeterProvider(encoder stdoutmetric.Encoder) (func(context.Context) error, error) {
	stdoutExporter, err := stdoutmetric.New(stdoutmetric.WithEncoder(encoder))
	if err != nil {
		return nil, fmt.Errorf("create stdout exporter: %s", err)
	}
	reader, err := otelprom.New()
	if err != nil {
		return nil, fmt.Errorf("create prometheus reader: %s", err)
	}
	meterProvider := metric.NewMeterProvider(
		metric.WithReader(reader),
		metric.WithReader(metric.NewPeriodicReader(stdoutExporter, metric.WithInterval(nperfmetric.PollInerval))),
	)
	otel.SetMeterProvider(meterProvider)
	return meterProvider.Shutdown, nil
}

func (o *Options) Run(ctx context.Context) error {
	fp, err := nperfmetric.NewFilterPrinter(o.IncludeNames, o.ExcludeNames, o.IncludeAttributes, o.ExcludeAttributes)
	if err != nil {
		return err
	}
	shutdownMeterProvider, err := initMeterProvider(fp)
	if err != nil {
		return fmt.Errorf("failed to create meter provider: %s", err)
	}
	closeMetricMeter, err := nperfmetric.ConfigureMetricMeter(otel.GetMeterProvider().Meter("nperf"))
	if err != nil {
		return fmt.Errorf("failed to configure metric meter: %s", err)
	}

	// Process
	var procMonitor process.Monitor
	go procMonitor.Run(ctx)

	// DNS
	dnsMonitor := &dns.Monitor{}
	if !o.DisableDNS {
		dnsMonitor, err = dns.NewMonitor()
		if err != nil {
			return fmt.Errorf("failed to create DNS Monitor: %s", err)
		}
		go dnsMonitor.Run(ctx)
	}

	// eBPF
	stopebpf := func() {}
	if !o.DisableeBPF {
		stopebpf, err = nperfebpf.Start(ctx, dnsMonitor, &procMonitor)
		if err != nil {
			return fmt.Errorf("failed to start ebpf programs: %s", err)
		}
	}

	// HTTP server
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/debug/dns/answers", func(w http.ResponseWriter, r *http.Request) {
		dnsMonitor.DumpAnswers(w)
	})
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
		closeMetricMeter()
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
		LogLevel:          slog.LevelInfo.String(),
		Output:            "",
		OutputFormat:      "json",
		Port:              7000,
		DisableDNS:        false,
		DisableeBPF:       false,
		IncludeNames:      []string{},
		ExcludeNames:      []string{},
		IncludeAttributes: []string{},
		ExcludeAttributes: []string{},
	}
	cmd := &cobra.Command{
		Use:          "ntop",
		SilenceUsage: true,
	}
	cmd.Flags().StringVarP(&o.LogLevel, "loglevel", "l", o.LogLevel, "log level")
	cmd.Flags().StringVarP(&o.Output, "output", "o", o.Output, "write output to this file instead of stdout")
	cmd.Flags().StringVar(&o.OutputFormat, "output-format", o.OutputFormat, "write output in this format")
	cmd.Flags().IntVarP(&o.Port, "port", "p", o.Port, "port to listen on")
	cmd.Flags().BoolVar(&o.DisableDNS, "disable-dns", o.DisableDNS, "disable DNS monitoring")
	cmd.Flags().BoolVar(&o.DisableeBPF, "disable-ebpf", o.DisableeBPF, "disable ebpf monitoring")
	cmd.Flags().StringArrayVar(&o.IncludeNames, "include", o.IncludeNames, `include these names in the output. inclusion is prioritized over exclusion. e.g., '^nperf_tcp_rtt$', '.*count$'`)
	cmd.Flags().StringArrayVar(&o.ExcludeNames, "exclude", o.ExcludeNames, `exclude these names in the output, e.g., '.*', 'nperf_tcp_.*'`)
	cmd.Flags().StringArrayVar(&o.IncludeAttributes, "include-attribute", o.IncludeAttributes, `include these attributes in the output. inclusion is prioritized over exclusion. e.g., 'pid:1234', 'domain:.*\.com$'`)
	cmd.Flags().StringArrayVar(&o.ExcludeAttributes, "exclude-attribute", o.ExcludeAttributes, `exclude these attributes in the output, e.g., 'process_name:.*', 'key:mustnot:have'`)
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
