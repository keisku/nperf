package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"

	"github.com/cilium/ebpf/rlimit"
	"github.com/keisku/nmon/dns"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
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

func initMeterProvider() (func(context.Context) error, error) {
	raeder, err := otelprom.New()
	if err != nil {
		return nil, fmt.Errorf("create prometheus reader: %s", err)
	}
	meterProvider := metric.NewMeterProvider(
		metric.WithReader(raeder),
		metric.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("nmon"),
		)),
	)
	otel.SetMeterProvider(meterProvider)
	return meterProvider.Shutdown, nil
}

func (o *Options) Run(ctx context.Context) error {
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
		"nmon.dns",
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
	slog.Info("received signal, exiting program...")
	if err := shutdownMeterProvider(context.Background()); err != nil {
		return fmt.Errorf("failed to shutdown meter provider: %s", err)
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
