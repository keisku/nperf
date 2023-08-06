#include "vmlinux.h"
#include "conn_tuple.h"
#include "map_defs.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// From include/net/tcp.h
// tcp_flag_byte(th) (((u_int8_t *)th)[13])
#define TCP_FLAGS_OFFSET 13

#define CONN_CLOSED_BATCH_SIZE 4

typedef enum
{
    CONN_DIRECTION_UNKNOWN = 0b00,
    CONN_DIRECTION_INCOMING = 0b01,
    CONN_DIRECTION_OUTGOING = 0b10,
} conn_direction_t;

typedef enum
{
    PACKET_COUNT_NONE = 0,
    PACKET_COUNT_ABSOLUTE = 1,
    PACKET_COUNT_INCREMENT = 2,
} packet_count_increment_t;

typedef struct
{
	__u8 layer_api;
	__u8 layer_application;
	__u8 layer_encryption;
	__u8 flags;
} protocol_stack_t;

typedef struct
{
	__u64 sent_bytes;
	__u64 recv_bytes;
	__u64 timestamp;
	__u32 flags;
	// "cookie" that uniquely identifies
	// a conn_stas_ts_t. This is used
	// in user space to distinguish between
	// stats for two or more connections that
	// may share the same conn_tuple_t (this can
	// happen when we're aggregating connections).
	// This is not the same as a TCP cookie or
	// the cookie in struct sock in the kernel
	__u32 cookie;
	__u64 sent_packets;
	__u64 recv_packets;
	__u8 direction;
	protocol_stack_t protocol_stack;
} conn_stats_ts_t;

typedef struct
{
	__u32 rtt;
	__u32 rtt_var;

	// Bit mask containing all TCP state transitions tracked by our tracer
	__u16 state_transitions;
} tcp_stats_t;

// Full data for a tcp connection
typedef struct
{
	conn_tuple_t tup;
	conn_stats_ts_t conn_stats;
	tcp_stats_t tcp_stats;
	__u32 tcp_retransmits;
} conn_t;

// This struct is meant to be used as a container for batching
// writes to the perf buffer. Ideally we should have an array of tcp_conn_t objects
// but apparently eBPF verifier doesn't allow arbitrary index access during runtime.
typedef struct
{
	conn_t c0;
	conn_t c1;
	conn_t c2;
	conn_t c3;
	__u16 len;
	__u64 id;
} batch_t;

typedef struct {
    struct sock *sk;
    int segs;
    __u32 retrans_out_pre;
} tcp_retransmit_skb_args_t;

/* This is a key/value store with the keys being a conn_tuple_t for send & recv calls
 * and the values being conn_stats_ts_t *.
 */
BPF_HASH_MAP(conn_stats, conn_tuple_t, conn_stats_ts_t, 1024)

/* This is a key/value store with the keys being a conn_tuple_t
 * and the values being a tcp_stats_t *.
 */
BPF_HASH_MAP(tcp_stats, conn_tuple_t, tcp_stats_t, 1024)

/*
 * Hash map to store conn_tuple_t to retransmits. We use a separate map
 * for retransmits from tcp_stats above since we don't normally
 * have the pid in the tcp_retransmit_skb kprobe
 */
BPF_HASH_MAP(tcp_retransmits, conn_tuple_t, __u32, 1024)

/* Will hold the PIDs initiating TCP connections */
BPF_HASH_MAP(tcp_ongoing_connect_pid, struct sock *, __u64, 1024)

// We use this map as a container for batching closed tcp/udp connections
BPF_PERCPU_HASH_MAP(conn_close_batch, __u32, batch_t, 1024)

/* Similar to pending_sockets this is used for capturing state between the call and return of the tcp_retransmit_skb() system call.
 *
 * Keys: the PID returned by bpf_get_current_pid_tgid()
 * Values: the args of the tcp_retransmit_skb call being instrumented.
 */
BPF_HASH_MAP(pending_tcp_retransmit_skb, __u64, tcp_retransmit_skb_args_t, 8192)

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} conn_close_event SEC(".maps");

static __always_inline void flush_conn_close_if_full(void *ctx)
{
	u32 cpu = bpf_get_smp_processor_id();
	batch_t *batch_ptr = bpf_map_lookup_elem(&conn_close_batch, &cpu);
	if (!batch_ptr)
	{
		return;
	}

	if (batch_ptr->len == CONN_CLOSED_BATCH_SIZE)
	{
		bpf_printk("Flushing conn_close_batch\n");
		bpf_ringbuf_output(&conn_close_event, batch_ptr, sizeof(*batch_ptr), 0);
	}
}

static __always_inline int get_proto(conn_tuple_t *t)
{
	return (t->metadata & CONN_TYPE_TCP) ? CONN_TYPE_TCP : CONN_TYPE_UDP;
}

static __always_inline void cleanup_conn(void *ctx, conn_tuple_t *tup, struct sock *sk)
{
	u32 cpu = bpf_get_smp_processor_id();

	// Will hold the full connection data to send through the perf buffer
	conn_t conn = {.tup = *tup};
	conn_stats_ts_t *cst = NULL;
	tcp_stats_t *tst = NULL;
	u32 *retrans = NULL;
	bool is_tcp = get_proto(&conn.tup) == CONN_TYPE_TCP;
	bool is_udp = get_proto(&conn.tup) == CONN_TYPE_UDP;

	if (is_tcp)
	{
		tst = bpf_map_lookup_elem(&tcp_stats, &(conn.tup));
		if (tst)
		{
			conn.tcp_stats = *tst;
			bpf_map_delete_elem(&tcp_stats, &(conn.tup));
		}

		conn.tup.pid = 0;
		retrans = bpf_map_lookup_elem(&tcp_retransmits, &(conn.tup));
		if (retrans)
		{
			conn.tcp_retransmits = *retrans;
			bpf_map_delete_elem(&tcp_retransmits, &(conn.tup));
		}
		conn.tup.pid = tup->pid;

		conn.tcp_stats.state_transitions |= (1 << TCP_CLOSE);
	}

	cst = bpf_map_lookup_elem(&conn_stats, &(conn.tup));
	if (is_udp && !cst)
	{
		return; // nothing to report
	}
	if (is_tcp && !cst && !tst && !retrans)
	{
		return; // nothing to report
	}

	if (cst)
	{
		conn.conn_stats = *cst;
		bpf_map_delete_elem(&conn_stats, &(conn.tup));
	}
	else
	{
		// we don't have any stats for the connection,
		// so cookie is not set, set it here
		conn.conn_stats.cookie = bpf_get_prandom_u32();
	}

	conn.conn_stats.timestamp = bpf_ktime_get_ns();

	// Batch TCP closed connections before generating a perf event
	batch_t *batch_ptr = bpf_map_lookup_elem(&conn_close_batch, &cpu);
	if (batch_ptr == NULL)
	{
		return;
	}

	// TODO: Can we turn this into a macro based on TCP_CLOSED_BATCH_SIZE?
	switch (batch_ptr->len)
	{
	case 0:
		batch_ptr->c0 = conn;
		batch_ptr->len++;
		return;
	case 1:
		batch_ptr->c1 = conn;
		batch_ptr->len++;
		return;
	case 2:
		batch_ptr->c2 = conn;
		batch_ptr->len++;
		return;
	case 3:
		batch_ptr->c3 = conn;
		batch_ptr->len++;
		// In this case the batch is ready to be flushed, which we defer to kretprobe/tcp_close
		// in order to cope with the eBPF stack limitation of 512 bytes.
		return;
	}

	// If we hit this section it means we had one or more interleaved tcp_close calls.
	// We send the connection outside of a batch anyway. This is likely not as
	// frequent of a case to cause performance issues and avoid cases where
	// we drop whole connections, which impacts things USM connection matching.
	bpf_ringbuf_output(&conn_close_event, &conn, sizeof(conn), 0);
}

static __always_inline int handle_retransmit(struct sock *sk, int count) {
    conn_tuple_t t = {};
    u64 zero = 0;
    if (!read_conn_tuple(&t, sk, zero, CONN_TYPE_TCP)) {
        return 0;
    }

    // initialize-if-no-exist the connection state, and load it
    u32 u32_zero = 0;
    bpf_map_update_elem(&tcp_retransmits, &t, &u32_zero, BPF_NOEXIST);
    u32 *val = bpf_map_lookup_elem(&tcp_retransmits, &t);
    if (val == NULL) {
        return 0;
    }

    __sync_fetch_and_add(val, count);

    return 0;
}

// update_tcp_stats update rtt, retransmission and state on of a TCP connection
static __always_inline void update_tcp_stats(conn_tuple_t *t, tcp_stats_t stats) {
    // initialize-if-no-exist the connection state, and load it
    tcp_stats_t empty = {};
    bpf_map_update_elem(&tcp_stats, t, &empty, BPF_NOEXIST);

    tcp_stats_t *val = bpf_map_lookup_elem(&tcp_stats, t);
    if (val == NULL) {
        return;
    }

    if (stats.rtt > 0) {
        // For more information on the bit shift operations see:
        // https://elixir.bootlin.com/linux/v4.6/source/net/ipv4/tcp.c#L2686
        val->rtt = stats.rtt >> 3;
        val->rtt_var = stats.rtt_var >> 2;
    }

    if (stats.state_transitions > 0) {
        val->state_transitions |= stats.state_transitions;
    }
}

static __always_inline void handle_tcp_stats(conn_tuple_t* t, struct sock* sk, u8 state) {
    u32 rtt = 0, rtt_var = 0;
    BPF_CORE_READ_INTO(&rtt, tcp_sk(sk), srtt_us);
    BPF_CORE_READ_INTO(&rtt_var, tcp_sk(sk), mdev_us);

    tcp_stats_t stats = { .rtt = rtt, .rtt_var = rtt_var };
    if (state > 0) {
        stats.state_transitions = (1 << state);
    }
    update_tcp_stats(t, stats);
}

static __always_inline int handle_message(conn_tuple_t *t, size_t sent_bytes, size_t recv_bytes, conn_direction_t dir,
    __u32 packets_out, __u32 packets_in, packet_count_increment_t segs_type, struct sock *sk) {
	// TODO: https://github.com/DataDog/datadog-agent/blob/5bf359eaf21bdbefa2ba3448b8cfb9ac229a974b/pkg/network/ebpf/c/tracer/stats.h#L161
    return 0;
}

static __always_inline int handle_tcp_recv(u64 pid_tgid, struct sock *skp, int recv) {
    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, skp, pid_tgid, CONN_TYPE_TCP)) {
        return 0;
    }

    handle_tcp_stats(&t, skp, 0);

    __u32 packets_in = 0;
    __u32 packets_out = 0;
    get_tcp_segment_counts(skp, &packets_in, &packets_out);

    return handle_message(&t, 0, recv, CONN_DIRECTION_UNKNOWN, packets_out, packets_in, PACKET_COUNT_ABSOLUTE, skp);
}
