// go:build ignore

#include "vmlinux.h"
#include "map_defs.h"
#include "conn_tuple.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
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

typedef struct
{
	__u32 pid;
	__u32 fd;
} pid_fd_t;

// This map is used to to temporarily store function arguments (sockfd) for
// sockfd_lookup_light function calls, so they can be accessed by the corresponding kretprobe.
// * Key is the pid_tgid;
// * Value the socket FD;
BPF_HASH_MAP(sockfd_lookup_args, __u64, __u32, 1024)

BPF_HASH_MAP(sock_by_pid_fd, pid_fd_t, struct sock *, 1024)

BPF_HASH_MAP(pid_fd_by_sock, struct sock *, pid_fd_t, 1024)

static __always_inline void clear_sockfd_maps(struct sock *sock)
{
	if (sock == NULL)
	{
		return;
	}

	pid_fd_t *pid_fd = bpf_map_lookup_elem(&pid_fd_by_sock, &sock);
	if (pid_fd == NULL)
	{
		return;
	}

	// Copy map value to stack before re-using it (needed for Kernel 4.4)
	pid_fd_t pid_fd_copy = {};
	pid_fd = &pid_fd_copy;

	bpf_map_delete_elem(&sock_by_pid_fd, pid_fd);
	bpf_map_delete_elem(&pid_fd_by_sock, &sock);
}

/* Will hold the PIDs initiating TCP connections */
BPF_HASH_MAP(tcp_ongoing_connect_pid, struct sock *, __u64, 1024)

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

static __always_inline void flush_conn_close_if_full(void *ctx) {}

SEC("fexit/tcp_close")
int BPF_PROG(tcp_close_exit, struct sock *sk, long timeout)
{
	bpf_printk("fexit/tcp_close\n");

	flush_conn_close_if_full(ctx);
	return 0;
}
