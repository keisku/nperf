package ebpf

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/ebpf/link"
	"golang.org/x/exp/slog"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -no-global-types -type conn_tuple_t -type conn_stats_ts_t bpf ./c/bpf_prog.c -- -I./c

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
		var connTuple bpfConnTupleT
		var connStats bpfConnStatsTsT
		// connsByTuple is used to detect whether we are iterating over
		// a connection we have previously seen. This can happen when
		// ebpf maps are being iterated over and deleted at the same time.
		// The iteration can reset when that happens.
		// See https://justin.azoff.dev/blog/bpf_map_get_next_key-pitfalls/
		connsByTuple := make(map[bpfConnTupleT]struct{})
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
				connStatsIter := objs.ConnStats.Iterate()
				for connStatsIter.Next(&connTuple, &connStats) {
					if _, ok := connsByTuple[connTuple]; ok {
						slog.Warn("duplicate connTuple", slog.Any("connTuple", connTuple))
						continue
					}
					slog.Info("conn_tuple and conn_stats", slog.Any("connTuple", connTuple), slog.Any("connStats", connStats))
				}
				if err := connStatsIter.Err(); err != nil {
					slog.Warn("can't iterate over connStats", slog.Any("error", err))
				}
			}
		}
	}()
	return cancel, nil
}
