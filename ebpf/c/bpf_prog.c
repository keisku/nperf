#include "vmlinux.h"
#include "conn_tuple.h"
#include "sock.h"
#include "tcp.h"
#include "port.h"
#include "bind.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("fexit/tcp_sendmsg")
int BPF_PROG(tcp_sendmsg_exit, struct sock *sk, struct msghdr *msg, size_t size, int sent) {
    bpf_printk("fexit/tcp_sendmsg");
    if (sent < 0) {
        bpf_printk("fexit/tcp_sendmsg: tcp_sendmsg err=%d\n", sent);
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_printk("fexit/tcp_sendmsg: pid_tgid: %d, sent: %d, sock: %llx\n", pid_tgid, sent, sk);

    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, sk, pid_tgid, CONN_TYPE_TCP)) {
        return 0;
    }

    handle_tcp_stats(&t, sk, 0);

    __u32 packets_in = 0;
    __u32 packets_out = 0;
    get_tcp_segment_counts(sk, &packets_in, &packets_out);

    return handle_message(&t, sent, 0, CONN_DIRECTION_UNKNOWN, packets_out, packets_in, PACKET_COUNT_ABSOLUTE, sk);
}

SEC("fexit/tcp_sendpage")
int BPF_PROG(tcp_sendpage_exit, struct sock *sk, struct page *page, int offset, size_t size, int flags, int sent) {
    bpf_printk("fexit/tcp_sendpage");
    if (sent < 0) {
        bpf_printk("fexit/tcp_sendpage: err=%d\n", sent);
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_printk("fexit/tcp_sendpage: pid_tgid: %d, sent: %d, sock: %llx\n", pid_tgid, sent, sk);

    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, sk, pid_tgid, CONN_TYPE_TCP)) {
        return 0;
    }

    handle_tcp_stats(&t, sk, 0);

    __u32 packets_in = 0;
    __u32 packets_out = 0;
    get_tcp_segment_counts(sk, &packets_in, &packets_out);

    return handle_message(&t, sent, 0, CONN_DIRECTION_UNKNOWN, packets_out, packets_in, PACKET_COUNT_ABSOLUTE, sk);
}

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

SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sk) {
    bpf_printk("fentry/tcp_connect");
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_printk("fentry/tcp_connect: tgid: %u, pid: %u\n", pid_tgid >> 32, pid_tgid & 0xFFFFFFFF);

    bpf_map_update_elem(&tcp_ongoing_connect_pid, &sk, &pid_tgid, BPF_ANY);

    return 0;
}

SEC("fentry/tcp_finish_connect")
int BPF_PROG(tcp_finish_connect, struct sock *sk, struct sk_buff *skb, int rc) {
    bpf_printk("fentry/tcp_finish_connect");
    u64 *pid_tgid_p = bpf_map_lookup_elem(&tcp_ongoing_connect_pid, &sk);
    if (!pid_tgid_p) {
        return 0;
    }

    u64 pid_tgid = *pid_tgid_p;
    bpf_map_delete_elem(&tcp_ongoing_connect_pid, &sk);
    bpf_printk("fentry/tcp_finish_connect: tgid: %u, pid: %u\n", pid_tgid >> 32, pid_tgid & 0xFFFFFFFF);

    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, sk, pid_tgid, CONN_TYPE_TCP)) {
        return 0;
    }

    handle_tcp_stats(&t, sk, TCP_ESTABLISHED);
    handle_message(&t, 0, 0, CONN_DIRECTION_OUTGOING, 0, 0, PACKET_COUNT_NONE, sk);

    bpf_printk("fentry/tcp_connect: netns: %u, sport: %u, dport: %u\n", t.netns, t.sport, t.dport);

    return 0;
}

SEC("fexit/inet_csk_accept")
int BPF_PROG(inet_csk_accept_exit, struct sock *_sk, int flags, int *err, bool kern, struct sock *sk) {
    bpf_printk("fexit/inet_csk_accept");
    if (sk == NULL) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_printk("fexit/inet_csk_accept: tgid: %u, pid: %u\n", pid_tgid >> 32, pid_tgid & 0xFFFFFFFF);

    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, sk, pid_tgid, CONN_TYPE_TCP)) {
        return 0;
    }
    handle_tcp_stats(&t, sk, TCP_ESTABLISHED);
    handle_message(&t, 0, 0, CONN_DIRECTION_INCOMING, 0, 0, PACKET_COUNT_NONE, sk);

    port_binding_t pb = {};
    pb.netns = t.netns;
    pb.port = t.sport;
    add_port_bind(&pb, port_bindings);
    bpf_printk("fexit/inet_csk_accept: netns: %u, sport: %u, dport: %u\n", t.netns, t.sport, t.dport);
    return 0;
}

SEC("fentry/inet_csk_listen_stop")
int BPF_PROG(inet_csk_listen_stop, struct sock *sk) {
    bpf_printk("fentry/inet_csk_listen_stop");
    __u16 lport = read_sport(sk);
    if (lport == 0) {
        bpf_printk("ERR(inet_csk_listen_stop): lport is 0 \n");
        return 0;
    }

    port_binding_t pb = {};
    pb.netns = get_netns_from_sock(sk);
    pb.port = lport;
    remove_port_bind(&pb, &port_bindings);
    bpf_printk("fentry/inet_csk_listen_stop: net ns: %u, lport: %u\n", pb.netns, pb.port);
    return 0;
}

SEC("fentry/inet_bind")
int BPF_PROG(inet_bind, struct socket *sock, struct sockaddr *uaddr, int addr_len) {
    bpf_printk("fentry/inet_bind\n");
    return sys_enter_bind(sock, uaddr);
}

SEC("fexit/inet_bind")
int BPF_PROG(inet_bind_exit, struct socket *sock, struct sockaddr *uaddr, int addr_len, int rc) {
    bpf_printk("fexit/inet_bind: rc=%d\n", rc);
    return sys_exit_bind(rc);
}

SEC("fentry/inet6_bind")
int BPF_PROG(inet6_bind, struct socket *sock, struct sockaddr *uaddr, int addr_len) {
    bpf_printk("fentry/inet6_bind\n");
    return sys_enter_bind(sock, uaddr);
}

SEC("fexit/inet6_bind")
int BPF_PROG(inet6_bind_exit, struct socket *sock, struct sockaddr *uaddr, int addr_len, int rc) {
    bpf_printk("fexit/inet6_bind: rc=%d\n", rc);
    return sys_exit_bind(rc);
}
