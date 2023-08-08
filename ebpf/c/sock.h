#include "vmlinux.h"
#include "ip.h"
#include "conn_tuple.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// source include/net/inet_sock.h
#define inet_daddr sk.__sk_common.skc_daddr
#define inet_dport sk.__sk_common.skc_dport

static __always_inline struct tcp_sock *tcp_sk(const struct sock *sk) {
    return (struct tcp_sock *)sk;
}

static __always_inline __u32 get_netns_from_sock(struct sock *sk) {
    void *skc_net = NULL;
    __u32 net_ns_inum = 0;
    bpf_probe_read_kernel(&skc_net, sizeof(void *), ((char *)sk));
    bpf_probe_read_kernel(&net_ns_inum, sizeof(net_ns_inum), ((char *)skc_net));
    return net_ns_inum;
}

static __always_inline u16 _sk_family(struct sock *skp) {
    u16 family = 0;
    BPF_CORE_READ_INTO(&family, &(skp->__sk_common), skc_family);
    return family;
}

static __always_inline struct inet_sock *inet_sk(const struct sock *sk) {
    return (struct inet_sock *)sk;
}

static __always_inline u32 read_saddr_v4(struct sock *skp) {
    u32 saddr = 0;
    BPF_CORE_READ_INTO(&saddr, &(skp->__sk_common), skc_rcv_saddr);
    if (saddr == 0) {
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

static __always_inline u16 read_sport(struct sock *skp) {
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

static __always_inline void read_in6_addr(u64 *addr_h, u64 *addr_l, const struct in6_addr *in6) {
    BPF_CORE_READ_INTO(addr_h, in6, in6_u.u6_addr32[0]);
    BPF_CORE_READ_INTO(addr_l, in6, in6_u.u6_addr32[2]);
}

static __always_inline void read_saddr_v6(struct sock *skp, u64 *addr_h, u64 *addr_l) {
    struct in6_addr in6 = {};
    BPF_CORE_READ_INTO(&in6, &(skp->__sk_common), skc_v6_rcv_saddr);
    read_in6_addr(addr_h, addr_l, &in6);
}

static __always_inline void read_daddr_v6(struct sock *skp, u64 *addr_h, u64 *addr_l) {
    struct in6_addr in6 = {};
    BPF_CORE_READ_INTO(&in6, &(skp->__sk_common), skc_v6_daddr);
    read_in6_addr(addr_h, addr_l, &in6);
}

/* check if IPs are IPv4 mapped to IPv6 ::ffff:xxxx:xxxx
 * https://tools.ietf.org/html/rfc4291#section-2.5.5
 * the addresses are stored in network byte order so IPv4 adddress is stored
 * in the most significant 32 bits of part saddr_l and daddr_l.
 * Meanwhile the end of the mask is stored in the least significant 32 bits.
 */
// On older kernels, clang can generate Wunused-function warnings on static inline functions defined in
// header files, even if they are later used in source files. __maybe_unused prevents that issue
static __always_inline bool is_ipv4_mapped_ipv6(__u64 saddr_h, __u64 saddr_l, __u64 daddr_h, __u64 daddr_l) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((saddr_h == 0 && ((__u32)saddr_l == 0xFFFF0000)) || (daddr_h == 0 && ((__u32)daddr_l == 0xFFFF0000)));
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return ((saddr_h == 0 && ((__u32)(saddr_l >> 32) == 0x0000FFFF)) || (daddr_h == 0 && ((__u32)(daddr_l >> 32) == 0x0000FFFF)));
#else
#error "Fix your compiler's __BYTE_ORDER__?!"
#endif
}

static __always_inline int read_conn_tuple(conn_tuple_t *t, struct sock *skp, u64 pid_tgid, metadata_mask_t type) {
    int err = 0;
    t->pid = pid_tgid >> 32;
    t->metadata = type;

    // Retrieve network namespace id first since addresses and ports may not be available for unconnected UDP
    // sends
    t->netns = get_netns_from_sock(skp);
    u16 family = _sk_family(skp);
    if (family == AF_INET) {
        t->metadata |= CONN_V4;
        if (t->saddr_l == 0) {
            t->saddr_l = read_saddr_v4(skp);
        }
        if (t->daddr_l == 0) {
            t->daddr_l = read_daddr_v4(skp);
        }
        if (t->saddr_l == 0 || t->daddr_l == 0) {
            bpf_printk("ERR(read_conn_tuple.v4): src or dst addr not set src=%d, dst=%d\n", t->saddr_l, t->daddr_l);
            err = 1;
        }
    } else if (family == AF_INET6) {
        if (!(t->saddr_h || t->saddr_l)) {
            read_saddr_v6(skp, &t->saddr_h, &t->saddr_l);
        }
        if (!(t->daddr_h || t->daddr_l)) {
            read_daddr_v6(skp, &t->daddr_h, &t->daddr_l);
        }

        /* We can only pass 4 args to bpf_trace_printk */
        /* so split those 2 statements to be able to log everything */
        if (!(t->saddr_h || t->saddr_l)) {
            bpf_printk("ERR(read_conn_tuple.v6): src addr not set: src_l:%d,src_h:%d\n",
                t->saddr_l, t->saddr_h);
            err = 1;
        }

        if (!(t->daddr_h || t->daddr_l)) {
            bpf_printk("ERR(read_conn_tuple.v6): dst addr not set: dst_l:%d,dst_h:%d\n",
                t->daddr_l, t->daddr_h);
            err = 1;
        }

        // Check if we can map IPv6 to IPv4
        if (is_ipv4_mapped_ipv6(t->saddr_h, t->saddr_l, t->daddr_h, t->daddr_l)) {
            t->metadata |= CONN_V4;
            t->saddr_h = 0;
            t->daddr_h = 0;
            t->saddr_l = (__u32)(t->saddr_l >> 32);
            t->daddr_l = (__u32)(t->daddr_l >> 32);
        } else {
            t->metadata |= CONN_V6;
        }
    } else {
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
