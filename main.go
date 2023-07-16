package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"

	"github.com/cilium/ebpf/rlimit"
	"github.com/keisku/nmon/dns"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slog"
)

type Options struct {
	Output       string
	OutputFormat string
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

func (o *Options) Run(ctx context.Context) error {
	dnsSnooper, err := dns.NewSnooper(dns.Config{})
	if err != nil {
		return fmt.Errorf("failed to create DNS snooper: %s", err)
	}
	dnsSnooper.Run(ctx)
	<-ctx.Done()
	slog.Info("received signal, exiting program...")
	return nil
}

func NewCmd() *cobra.Command {
	o := &Options{
		Output:       "",
		OutputFormat: "json",
	}
	cmd := &cobra.Command{
		Use:          "ntop",
		SilenceUsage: true,
	}
	cmd.Flags().StringVarP(&o.Output, "output", "o", o.Output, "write output to this file instead of stdout")
	cmd.Flags().StringVar(&o.OutputFormat, "output-format", o.OutputFormat, "write output in this format")
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

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalln(err)
	}

	if err := NewCmd().ExecuteContext(ctx); err != nil {
		log.Fatalln(err)
	}
}
