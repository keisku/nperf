package ebpf

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/ebpf/link"
	"golang.org/x/exp/slog"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -no-global-types bpf ./c/bpf_prog.c -- -I./c

var objs bpfObjects

// Start starts the eBPF program by loading the BPF objects and attaching tracing to the specified programs.
// It returns an error if it fails to load the BPF objects or attach tracing.
func Start(inCtx context.Context) (context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(inCtx)
	err := loadBpfObjects(&objs, nil)
	if err != nil {
		return cancel, fmt.Errorf("can't load bpf: %w", err)
	}
	linkTracingOptions := []link.TracingOptions{
		{Program: objs.TcpSendmsgExit},
		{Program: objs.TcpSendpageExit},
		{Program: objs.TcpClose},
		{Program: objs.TcpCloseExit},
		{Program: objs.TcpRecvmsgExit},
		{Program: objs.TcpRetransmitSkb},
		{Program: objs.TcpRetransmitSkbExit},
		{Program: objs.TcpConnect},
		{Program: objs.TcpFinishConnect},
		{Program: objs.InetCskAcceptExit},
		{Program: objs.InetCskListenStop},
		{Program: objs.InetBind},
		{Program: objs.InetBindExit},
		{Program: objs.Inet6Bind},
		{Program: objs.Inet6BindExit},
	}
	links := make([]link.Link, len(linkTracingOptions))
	for i, opt := range linkTracingOptions {
		links[i], err = link.AttachTracing(opt)
		if err != nil {
			return cancel, fmt.Errorf("can't attach tracing: %w", err)
		}
	}
	go func() {
		metricsCollectionTicker := time.NewTicker(time.Second)
		for {
			select {
			case <-ctx.Done():
				slog.Info("exiting ebpf programs...")
				if err := objs.Close(); err != nil {
					slog.Warn("can't close bpf objects", slog.Any("error", err))
				}
				for i := range links {
					if err := links[i].Close(); err != nil {
						slog.Warn("can't close tracing", slog.Any("error", err))
					}
				}
				return
			case <-metricsCollectionTicker.C:
				// TODO: iterate ebpf maps to collect metrics
			}
		}
	}()
	return cancel, nil
}
