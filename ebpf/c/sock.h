#include "vmlinux.h"
#include "ip.h"
#include "conn_tuple.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// source include/net/inet_sock.h
#define inet_daddr sk.__sk_common.skc_daddr
#define inet_dport sk.__sk_common.skc_dport

/* The LOAD_CONSTANT macro is used to define a named constant that will be replaced
 * at runtime by the Go code. This replaces usage of a bpf_map for storing values, which
 * eliminates a bpf_map_lookup_elem per kprobe hit. The constants are best accessed with a
 * dedicated inlined function.
 */
#define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" \
									  : "=r"(var))

static __always_inline __u64 offset_netns()
{
	__u64 val = 0;
	LOAD_CONSTANT("offset_netns", val);
	return val;
}

static __always_inline __u64 offset_ino()
{
	__u64 val = 0;
	LOAD_CONSTANT("offset_ino", val);
	return val;
}

static __always_inline struct tcp_sock *tcp_sk(const struct sock *sk) 
{
	return (struct tcp_sock *)sk;
}

static __always_inline struct sock *socket_sk(struct socket *sock)
{
	struct sock *sk = NULL;
	BPF_CORE_READ_INTO(&sk, sock, sk);
	return sk;
}

static __always_inline __u32 get_netns_from_sock(struct sock *sk)
{
	void *skc_net = NULL;
	__u32 net_ns_inum = 0;
	bpf_probe_read_kernel(&skc_net, sizeof(void *), ((char *)sk) + offset_netns());
	bpf_probe_read_kernel(&net_ns_inum, sizeof(net_ns_inum), ((char *)skc_net) + offset_ino());
	return net_ns_inum;
}

static __always_inline u16 _sk_family(struct sock *skp)
{
	u16 family = 0;
	BPF_CORE_READ_INTO(&family, &(skp->__sk_common), skc_family);
	return family;
}

static __always_inline struct inet_sock *inet_sk(const struct sock *sk)
{
	return (struct inet_sock *)sk;
}

static __always_inline u32 read_saddr_v4(struct sock *skp)
{
	u32 saddr = 0;
	BPF_CORE_READ_INTO(&saddr, &(skp->__sk_common), skc_rcv_saddr);
	if (saddr == 0)
	{
		BPF_CORE_READ_INTO(&saddr, inet_sk(skp), inet_saddr);
	}
	return saddr;
}

static __always_inline u32 read_daddr_v4(struct sock *skp)
{
	u32 daddr = 0;
	BPF_CORE_READ_INTO(&daddr, &(skp->__sk_common), skc_daddr);
	if (daddr == 0)
	{
		BPF_CORE_READ_INTO(&daddr, inet_sk(skp), inet_daddr);
	}
	return daddr;
}

static __always_inline u16 read_sport(struct sock *skp)
{
	// try skc_num, then inet_sport
	u16 sport = 0;
	BPF_CORE_READ_INTO(&sport, &(skp->__sk_common), skc_num);
	if (sport == 0)
	{
		BPF_CORE_READ_INTO(&sport, inet_sk(skp), inet_sport);
		sport = bpf_ntohs(sport);
	}
	return sport;
}

static u16 read_dport(struct sock *skp)
{
	u16 dport = 0;
	bpf_probe_read_kernel(&dport, sizeof(dport), &(skp->__sk_common).skc_dport);
	BPF_CORE_READ_INTO(&dport, &(skp->__sk_common), skc_dport);
	if (dport == 0)
	{
		BPF_CORE_READ_INTO(&dport, inet_sk(skp), inet_dport);
	}
	return bpf_ntohs(dport);
}

static __always_inline int read_conn_tuple(conn_tuple_t *t, struct sock *skp, u64 pid_tgid, metadata_mask_t type)
{
	int err = 0;
	t->pid = pid_tgid >> 32;
	t->metadata = type;

	// Retrieve network namespace id first since addresses and ports may not be available for unconnected UDP
	// sends
	t->netns = get_netns_from_sock(skp);
	u16 family = _sk_family(skp);
	if (family == AF_INET)
	{
		t->metadata |= CONN_V4;
		if (t->saddr_l == 0)
		{
			t->saddr_l = read_saddr_v4(skp);
		}
		if (t->daddr_l == 0)
		{
			t->daddr_l = read_daddr_v4(skp);
		}
		if (t->saddr_l == 0 || t->daddr_l == 0)
		{
			bpf_printk("ERR(read_conn_tuple.v4): src or dst addr not set src=%d, dst=%d\n", t->saddr_l, t->daddr_l);
			err = 1;
		}
	}
	else if (family == AF_INET6)
	{
		// Implement: https://github.com/DataDog/datadog-agent/blob/5bf359eaf21bdbefa2ba3448b8cfb9ac229a974b/pkg/network/ebpf/c/sock.h#L204-L238
	}
	else
	{
		bpf_printk("Unknown family: %d\n", family);
		err = 1;
	}

	// Retrieve ports
	if (t->sport == 0)
	{
		t->sport = read_sport(skp);
	}
	if (t->dport == 0)
	{
		t->dport = read_dport(skp);
	}

	if (t->sport == 0 || t->dport == 0)
	{
		bpf_printk("ERR(read_conn_tuple.v4): src/dst port not set: src:%d, dst:%d\n", t->sport, t->dport);
		err = 1;
	}

	return err ? 0 : 1;
}

static __always_inline void get_tcp_segment_counts(struct sock* skp, __u32* packets_in, __u32* packets_out) {
    BPF_CORE_READ_INTO(packets_out, tcp_sk(skp), segs_out);
    BPF_CORE_READ_INTO(packets_in, tcp_sk(skp), segs_in);
}
