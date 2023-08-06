#include "vmlinux.h"
#include "map_defs.h"
#include "conn_tuple.h"
#include "sock.h"
#include "sockfd.h"
#include "tcp.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define TASK_COMM_LEN 16

char LICENSE[] SEC("license") = "GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

/**
 * The sample submitted to userspace over a ring buffer.
 * Emit struct event's type info into the ELF's BTF so bpf2go
 * can generate a Go type from it.
 */
struct event
{
	u8 comm[16];
	__u16 sport;
	__be16 dport;
	__be32 saddr;
	__be32 daddr;
};
struct event *unused __attribute__((unused));

SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sk)
{
	if (sk->__sk_common.skc_family != AF_INET)
	{
		return 0;
	}

	struct event *tcp_info;
	tcp_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!tcp_info)
	{
		return 0;
	}

	tcp_info->saddr = sk->__sk_common.skc_rcv_saddr;
	tcp_info->daddr = sk->__sk_common.skc_daddr;
	tcp_info->dport = sk->__sk_common.skc_dport;
	tcp_info->sport = bpf_htons(sk->__sk_common.skc_num);

	bpf_get_current_comm(&tcp_info->comm, TASK_COMM_LEN);

	bpf_ringbuf_submit(tcp_info, 0);

	return 0;
}

SEC("fentry/tcp_close")
int BPF_PROG(tcp_close, struct sock *sk, long timeout)
{
	conn_tuple_t t = {};
	u64 pid_tgid = bpf_get_current_pid_tgid();

	bpf_printk("fentry/tcp_close: pid_tgid: %d\n", pid_tgid >> 32);

	// Should actually delete something only if the connection never got established
	bpf_map_delete_elem(&tcp_ongoing_connect_pid, &sk);

	clear_sockfd_maps(sk);

	// Get network namespace id
	if (!read_conn_tuple(&t, sk, pid_tgid, CONN_TYPE_TCP))
	{
		return 0;
	}
	bpf_printk("fentry/tcp_close: netns: %u, sport: %u, dport: %u\n", t.netns, t.sport, t.dport);

	cleanup_conn(ctx, &t, sk);
	return 0;
}

SEC("fexit/tcp_close")
int BPF_PROG(tcp_close_exit, struct sock *sk, long timeout)
{
	bpf_printk("fexit/tcp_close\n");

	flush_conn_close_if_full(ctx);
	return 0;
}

SEC("fentry/sockfd_lookup_light")
int BPF_PROG(sockfd_lookup_light, int fd, int *err, int *fput_needed, struct socket *socket)
{
	bpf_printk("fentry/sockfd_lookup_light\n");
	u64 pid_tgid = bpf_get_current_pid_tgid();

	// Check if have already a map entry for this pid_fd_t
	// TODO: This lookup eliminates *4* map operations for existing entries
	// but can reduce the accuracy of programs relying on socket FDs for
	// processes with a lot of FD churn
	pid_fd_t key = {
		.pid = pid_tgid >> 32,
		.fd = fd,
	};
	struct sock **sock = bpf_map_lookup_elem(&sock_by_pid_fd, &key);
	if (sock != NULL)
	{
		return 0;
	}

	bpf_map_update_elem(&sockfd_lookup_args, &pid_tgid, &fd, BPF_ANY);
	return 0;
}

// * an index of pid_fd_t to a struct sock*;
// * an index of struct sock* to pid_fd_t;
SEC("fexit/sockfd_lookup_light")
int BPF_PROG(sockfd_lookup_light_exit, int fd, int *err, int *fput_needed, struct socket *socket)
{
	bpf_printk("fexit/sockfd_lookup_light\n");
    u64 pid_tgid = bpf_get_current_pid_tgid();
    // Check if have already a map entry for this pid_fd_t
    // TODO: This lookup eliminates *4* map operations for existing entries
    // but can reduce the accuracy of programs relying on socket FDs for
    // processes with a lot of FD churn
    pid_fd_t key = {
        .pid = pid_tgid >> 32,
        .fd = fd,
    };

    struct sock **skpp = bpf_map_lookup_elem(&sock_by_pid_fd, &key);
    if (skpp != NULL) {
        return 0;
    }

    // For now let's only store information for TCP sockets
    const struct proto_ops *proto_ops = BPF_CORE_READ(socket, ops);
    if (!proto_ops) {
        return 0;
    }

    enum sock_type sock_type = BPF_CORE_READ(socket, type);
    int family = BPF_CORE_READ(proto_ops, family);
    if (sock_type != SOCK_STREAM || !(family == AF_INET || family == AF_INET6)) {
        return 0;
    }

    // Retrieve struct sock* pointer from struct socket*
    struct sock *sock = BPF_CORE_READ(socket, sk);

    pid_fd_t pid_fd = {
        .pid = pid_tgid >> 32,
        .fd = fd,
    };

    // These entries are cleaned up by tcp_close
    bpf_map_update_elem(&pid_fd_by_sock, &sock, &pid_fd, BPF_ANY);
    bpf_map_update_elem(&sock_by_pid_fd, &pid_fd, &sock, BPF_ANY);

	return 0;
}

SEC("fentry/tcp_retransmit_skb")
int BPF_PROG(tcp_retransmit_skb, struct sock *sk, struct sk_buff *skb, int segs, int err) {
    bpf_printk("fexntry/tcp_retransmit\n");
    u64 tid = bpf_get_current_pid_tgid();
    tcp_retransmit_skb_args_t args = {};
    args.retrans_out_pre = BPF_CORE_READ(tcp_sk(sk), retrans_out);
    if (args.retrans_out_pre < 0) {
        return 0;
    }

    bpf_map_update_elem(&pending_tcp_retransmit_skb, &tid, &args, BPF_ANY);

    return 0;
}

SEC("fexit/tcp_retransmit_skb")
int BPF_PROG(tcp_retransmit_skb_exit, struct sock *sk, struct sk_buff *skb, int segs, int err) {
    bpf_printk("fexit/tcp_retransmit\n");
    u64 tid = bpf_get_current_pid_tgid();
    if (err < 0) {
        bpf_map_delete_elem(&pending_tcp_retransmit_skb, &tid);
        return 0;
    }
    tcp_retransmit_skb_args_t *args = bpf_map_lookup_elem(&pending_tcp_retransmit_skb, &tid);
    if (args == NULL) {
        return 0;
    }
    u32 retrans_out_pre = args->retrans_out_pre;
    u32 retrans_out = BPF_CORE_READ(tcp_sk(sk), retrans_out);
    bpf_map_delete_elem(&pending_tcp_retransmit_skb, &tid);

    if (retrans_out < 0) {
        return 0;
    }

    return handle_retransmit(sk, retrans_out-retrans_out_pre);
}

SEC("fexit/tcp_recvmsg")
int BPF_PROG(tcp_recvmsg_exit, struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len, int copied) {
    bpf_printk("fexit/tcp_recvmsg");
    if (copied < 0) { // error
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    return handle_tcp_recv(pid_tgid, sk, copied);
}
