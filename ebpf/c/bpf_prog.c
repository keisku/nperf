#include "vmlinux.h"
#include "conn_tuple.h"
#include "sock.h"
#include "tcp.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("fentry/tcp_close")
int BPF_PROG(tcp_close, struct sock *sk, long timeout) {
    conn_tuple_t t = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_printk("fentry/tcp_close: pid_tgid: %d\n", pid_tgid >> 32);

    // Should actually delete something only if the connection never got established
    bpf_map_delete_elem(&tcp_ongoing_connect_pid, &sk);

    // Get network namespace id
    if (!read_conn_tuple(&t, sk, pid_tgid, CONN_TYPE_TCP)) {
        return 0;
    }
    bpf_printk("fentry/tcp_close: netns: %u, sport: %u, dport: %u\n", t.netns, t.sport, t.dport);

    cleanup_conn(ctx, &t, sk);
    return 0;
}

SEC("fexit/tcp_close")
int BPF_PROG(tcp_close_exit, struct sock *sk, long timeout) {
    bpf_printk("fexit/tcp_close\n");

    flush_conn_close_if_full(ctx);
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

    return handle_retransmit(sk, retrans_out - retrans_out_pre);
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
