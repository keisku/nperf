#include "vmlinux.h"
#include "ip.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// source include/net/inet_sock.h
#define inet_daddr sk.__sk_common.skc_daddr
#define inet_dport sk.__sk_common.skc_dport

// From include/net/tcp.h
// tcp_flag_byte(th) (((u_int8_t *)th)[13])
#define TCP_FLAGS_OFFSET 13

// Metadata bit masks
// 0 << x is only for readability
typedef enum
{
	// Connection type
	CONN_TYPE_UDP = 0,
	CONN_TYPE_TCP = 1,

	// Connection family
	CONN_V4 = 0 << 1,
	CONN_V6 = 1 << 1,
} metadata_mask_t;

typedef struct
{
	/* Using the type unsigned __int128 generates an error in the ebpf verifier */
	__u64 saddr_h;
	__u64 saddr_l;
	__u64 daddr_h;
	__u64 daddr_l;
	__u16 sport;
	__u16 dport;
	__u32 netns;
	__u32 pid;
	// Metadata description:
	// First bit indicates if the connection is TCP (1) or UDP (0)
	// Second bit indicates if the connection is V6 (1) or V4 (0)
	__u32 metadata; // This is that big because it seems that we atleast need a 32-bit aligned struct
} conn_tuple_t;

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

static __always_inline u32 read_daddr_v4(struct sock *skp) {
    u32 daddr = 0;
    BPF_CORE_READ_INTO(&daddr, &(skp->__sk_common), skc_daddr);
    if (daddr == 0) {
        BPF_CORE_READ_INTO(&daddr, inet_sk(skp), inet_daddr);
    }
    return daddr;
}

static __always_inline u16 read_sport(struct sock* skp) {
    // try skc_num, then inet_sport
    u16 sport = 0;
    BPF_CORE_READ_INTO(&sport, &(skp->__sk_common), skc_num);
    if (sport == 0) {
        BPF_CORE_READ_INTO(&sport, inet_sk(skp), inet_sport);
        sport = bpf_ntohs(sport);
    }
    return sport;
}

static u16 read_dport(struct sock *skp) {
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &(skp->__sk_common).skc_dport);
    BPF_CORE_READ_INTO(&dport, &(skp->__sk_common), skc_dport);
    if (dport == 0) {
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
    if (t->sport == 0) {
        t->sport = read_sport(skp);
    }
    if (t->dport == 0) {
        t->dport = read_dport(skp);
    }

    if (t->sport == 0 || t->dport == 0) {
        bpf_printk("ERR(read_conn_tuple.v4): src/dst port not set: src:%d, dst:%d\n", t->sport, t->dport);
        err = 1;
    }

	return err ? 0 : 1;
}

static __always_inline void cleanup_conn(void *ctx, conn_tuple_t *tup, struct sock *sk) {}
