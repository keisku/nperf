package ebpf

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/keisku/nperf/metric"
	utilnetip "github.com/keisku/nperf/util/netip"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/exp/slog"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -no-global-types -type conn_tuple_t -type conn_stats_ts_t -type tcp_stats_t bpf ./c/bpf_prog.c -- -I./c

type DNS interface {
	ReverseResolve(addrs []netip.Addr) (map[netip.Addr]string, map[string]string, error)
}

type noopDNS struct{}

func (noopDNS) ReverseResolve(addrs []netip.Addr) (map[netip.Addr]string, map[string]string, error) {
	return nil, nil, nil
}

var objs bpfObjects

// Start starts the eBPF program by loading the BPF objects and attaching tracing to the specified programs.
// It returns an error if it fails to load the BPF objects or attach tracing.
func Start(inCtx context.Context, dns DNS) (context.CancelFunc, error) {
	if dns == nil {
		dns = noopDNS{}
	}
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
		metricCollectionInterval := time.NewTicker(3 * metric.PollInerval)
		var connTuple bpfConnTupleT
		var connStats bpfConnStatsTsT
		var tcpStats bpfTcpStatsT
		var tcpRetransmits uint32
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
				metricCollectionInterval.Stop()
				if err := objs.Close(); err != nil {
					slog.Warn("can't close bpf objects", slog.Any("error", err))
				}
				for i := range links {
					if err := links[i].Close(); err != nil {
						slog.Warn("can't close tracing", slog.Any("error", err))
					}
				}
				return
			case <-metricCollectionInterval.C:
				connStatsIter := objs.ConnStats.Iterate()
				for connStatsIter.Next(&connTuple, &connStats) {
					if _, ok := connsByTuple[connTuple]; ok {
						slog.Debug("duplicate connTuple", slog.Any("conn_tuple", connTuple))
						continue
					}
					connsByTuple[connTuple] = struct{}{}
					saddr := utilnetip.FromLowHigh(connTuple.SaddrL, connTuple.SaddrH)
					daddr := utilnetip.FromLowHigh(connTuple.DaddrL, connTuple.DaddrH)
					attrs := []attribute.KeyValue{
						{Key: "saddr", Value: attribute.StringValue(saddr.String())},
						{Key: "daddr", Value: attribute.StringValue(daddr.String())},
						{Key: "sport", Value: attribute.Int64Value(int64(connTuple.Sport))},
						{Key: "dport", Value: attribute.Int64Value(int64(connTuple.Dport))},
						{Key: "netns", Value: attribute.Int64Value(int64(connTuple.Netns))},
						{Key: "pid", Value: attribute.Int64Value(int64(connTuple.Pid))},
					}
					domains, cnames, err := dns.ReverseResolve([]netip.Addr{saddr, daddr})
					if err == nil {
						attrs = append(attrs, resolveDomainAndCnamesToAttributes("saddr", saddr, domains, cnames)...)
						attrs = append(attrs, resolveDomainAndCnamesToAttributes("daddr", daddr, domains, cnames)...)
					} else {
						slog.Debug(err.Error(), slog.String("saddr", saddr.String()), slog.String("daddr", daddr.String()))
					}
					metric.Gauge(metric.TCPSentBytes, float64(connStats.SentBytes)/1000, attrs...)
					metric.Gauge(metric.TCPRecvBytes, float64(connStats.RecvBytes)/1000, attrs...)
					metric.Gauge(metric.TCPSentPackets, float64(connStats.SentPackets), attrs...)
					metric.Gauge(metric.TCPRecvPackets, float64(connStats.RecvPackets), attrs...)
					if err := objs.TcpStats.Lookup(&connTuple, &tcpStats); err == nil {
						metric.Gauge(metric.TCPRtt, float64(tcpStats.Rtt)/1000, attrs...)
						metric.Gauge(metric.TCPRttVar, float64(tcpStats.RttVar)/1000, attrs...)
					} else {
						slog.Warn("can't lookup tcpStats", slog.Any("error", err), slog.Any("conn_tuple", connTuple))
					}
					if err := objs.TcpRetransmits.Lookup(&connTuple, &tcpRetransmits); err == nil {
						// Don't log if there are no retransmits since it's a common & positive case.
						metric.Gauge(metric.TCPRetransmits, float64(tcpRetransmits), attrs...)
					}
				}
				if err := connStatsIter.Err(); err != nil {
					slog.Warn("can't iterate over connStats", slog.Any("error", err))
				}
			}
		}
	}()
	return cancel, nil
}

func resolveDomainAndCnamesToAttributes(key string, ipAddr netip.Addr, reverseDomain map[netip.Addr]string, reverseCname map[string]string) []attribute.KeyValue {
	var kvs []attribute.KeyValue
	domain, ok := reverseDomain[ipAddr]
	if !ok {
		return kvs
	}
	var resolvedCnames []string
	name := domain
	for {
		cname, ok := reverseCname[name]
		if !ok {
			break
		}
		name = cname
		resolvedCnames = append(resolvedCnames, name)
	}
	kvs = append(kvs, attribute.KeyValue{Key: attribute.Key(fmt.Sprintf("%s_domain", key)), Value: attribute.StringValue(name)})
	if 0 < len(resolvedCnames) {
		kvs = append(kvs, attribute.KeyValue{Key: attribute.Key(fmt.Sprintf("%s_cname", key)), Value: attribute.StringSliceValue(resolvedCnames)})
	}
	return kvs
}
