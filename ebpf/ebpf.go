package ebpf

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/ebpf/link"
	utilnetip "github.com/keisku/nperf/util/netip"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/exp/slog"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -no-global-types -type conn_tuple_t -type conn_stats_ts_t -type tcp_stats_t bpf ./c/bpf_prog.c -- -I./c

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
		metricsCollectionTicker := time.NewTicker(300 * time.Millisecond)
		var connTuple bpfConnTupleT
		var connStats bpfConnStatsTsT
		var tcpStats bpfTcpStatsT
		for {
			// connsByTuple is used to detect whether we are iterating over
			// a connection we have previously seen. This can happen when
			// ebpf maps are being iterated over and deleted at the same time.
			// The iteration can reset when that happens.
			// See https://justin.azoff.dev/blog/bpf_map_get_next_key-pitfalls/
			connsByTuple := make(map[bpfConnTupleT]struct{})
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
						slog.Debug("duplicate connTuple", slog.Any("conn_tuple", connTuple))
						continue
					}
					connsByTuple[connTuple] = struct{}{}
					if err := objs.TcpStats.Lookup(&connTuple, &tcpStats); err != nil {
						slog.Warn("can't lookup tcpStats", slog.Any("error", err), slog.Any("conn_tuple", connTuple))
						continue
					}
					attrs := []attribute.KeyValue{
						{Key: "saddr", Value: attribute.StringValue(utilnetip.FromLowHigh(connTuple.SaddrL, connTuple.SaddrH).String())},
						{Key: "daddr", Value: attribute.StringValue(utilnetip.FromLowHigh(connTuple.DaddrL, connTuple.DaddrH).String())},
						{Key: "sport", Value: attribute.Int64Value(int64(connTuple.Sport))},
						{Key: "dport", Value: attribute.Int64Value(int64(connTuple.Dport))},
						{Key: "netns", Value: attribute.Int64Value(int64(connTuple.Netns))},
						{Key: "pid", Value: attribute.Int64Value(int64(connTuple.Pid))},
					}
					sendDatapoint[float64](tcpSentBytesCh, datapoint[float64]{value: float64(connStats.SentBytes) / 1000, attributes: attrs})
					sendDatapoint[float64](tcpRecvBytesCh, datapoint[float64]{value: float64(connStats.RecvBytes) / 1000, attributes: attrs})
					sendDatapoint[float64](tcpRttCh, datapoint[float64]{value: float64(tcpStats.Rtt) / 1000, attributes: attrs})
					tcpRttHistgram.Record(ctx, float64(tcpStats.Rtt)/1000, metric.WithAttributes(attrs...))
					sendDatapoint[float64](tcpRttVarCh, datapoint[float64]{value: float64(tcpStats.RttVar) / 1000, attributes: attrs})
					tcpRttVarHistgram.Record(ctx, float64(tcpStats.RttVar)/1000, metric.WithAttributes(attrs...))
					sendDatapoint[int64](tcpSentPacketsCh, datapoint[int64]{value: int64(connStats.SentPackets), attributes: attrs})
					sendDatapoint[int64](tcpRecvPacketsCh, datapoint[int64]{value: int64(connStats.RecvPackets), attributes: attrs})
				}
				if err := connStatsIter.Err(); err != nil {
					slog.Warn("can't iterate over connStats", slog.Any("error", err))
				}
			}
		}
	}()
	return cancel, nil
}
