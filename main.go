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
	Output            string
	OutputFormat      string
	Port              int
	DisableDNS        bool
	DisableeBPF       bool
	IncludeNames      []string
	ExcludeNames      []string
	IncludeAttributes []string
	ExcludeAttributes []string

	includeNames      map[string]struct{}
	excludeNames      map[string]struct{}
	includeAttributes map[string]string
	excludeAttributes map[string]string
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
	for _, name := range o.IncludeNames {
		o.includeNames[name] = struct{}{}
	}
	for _, name := range o.ExcludeNames {
		o.excludeNames[name] = struct{}{}
	}
	for _, attr := range o.IncludeAttributes {
		kv := strings.Split(attr, ":")
		if len(kv) != 2 {
			slog.Warn("invalid input", slog.String("attribute", attr))
			continue
		}
		o.includeAttributes[kv[0]] = kv[1]
	}
	for _, attr := range o.ExcludeAttributes {
		kv := strings.Split(attr, ":")
		if len(kv) != 2 {
			slog.Warn("invalid input", slog.String("attribute", attr))
			continue
		}
		o.excludeAttributes[kv[0]] = kv[1]
	}
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
		// Every 100ms, write metrics to io.Writer of slog.
		metric.WithReader(metric.NewPeriodicReader(stdoutExporter, metric.WithInterval(nperfmetric.PollInerval))),
	)
	otel.SetMeterProvider(meterProvider)
	return meterProvider.Shutdown, nil
}

func (o *Options) Run(ctx context.Context) error {
	shutdownMeterProvider, err := initMeterProvider(nperfmetric.FilterPrinter{
		IncludeNames:      o.includeNames,
		ExcludeNames:      o.excludeNames,
		IncludeAttributes: o.includeAttributes,
		ExcludeAttributes: o.excludeAttributes,
	})
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
		Output:            "",
		OutputFormat:      "json",
		Port:              7000,
		DisableDNS:        false,
		DisableeBPF:       false,
		IncludeNames:      []string{},
		ExcludeNames:      []string{},
		IncludeAttributes: []string{},
		ExcludeAttributes: []string{},
		includeNames:      make(map[string]struct{}),
		excludeNames:      make(map[string]struct{}),
		includeAttributes: make(map[string]string),
		excludeAttributes: make(map[string]string),
	}
	cmd := &cobra.Command{
		Use:          "ntop",
		SilenceUsage: true,
	}
	cmd.Flags().StringVarP(&o.Output, "output", "o", o.Output, "write output to this file instead of stdout")
	cmd.Flags().StringVar(&o.OutputFormat, "output-format", o.OutputFormat, "write output in this format")
	cmd.Flags().IntVarP(&o.Port, "port", "p", o.Port, "port to listen on")
	cmd.Flags().BoolVar(&o.DisableDNS, "disable-dns", o.DisableDNS, "disable DNS monitoring")
	cmd.Flags().BoolVar(&o.DisableeBPF, "disable-ebpf", o.DisableeBPF, "disable ebpf monitoring")
	cmd.Flags().StringArrayVar(&o.IncludeNames, "include", o.IncludeNames, `include these names in the output. include is prioritized over exclude. e.g., "nperf_tcp_rtt"`)
	cmd.Flags().StringArrayVar(&o.ExcludeNames, "exclude", o.ExcludeNames, `exclude these names in the output, e.g., "nperf_tcp_rtt"`)
	cmd.Flags().StringArrayVar(&o.IncludeAttributes, "include-attribute", o.IncludeAttributes, "include these attributes in the output. include is prioritized over exclude. e.g., key:value")
	cmd.Flags().StringArrayVar(&o.ExcludeAttributes, "exclude-attribute", o.ExcludeAttributes, "exclude these attributes in the output, e.g, key:value")
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
