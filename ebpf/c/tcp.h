#include "vmlinux.h"
#include "conn_tuple.h"
#include "map_defs.h"
#include "cookie.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// From include/net/tcp.h
// tcp_flag_byte(th) (((u_int8_t *)th)[13])
#define TCP_FLAGS_OFFSET 13

#define CONN_CLOSED_BATCH_SIZE 4

#define FLAG_FULLY_CLASSIFIED 1 << 0
#define FLAG_USM_ENABLED 1 << 1
#define FLAG_NPM_ENABLED 1 << 2
#define FLAG_TCP_CLOSE_DELETION 1 << 3
#define FLAG_SOCKET_FILTER_DELETION 1 << 4

typedef enum {
    CONN_DIRECTION_UNKNOWN = 0b00,
    CONN_DIRECTION_INCOMING = 0b01,
    CONN_DIRECTION_OUTGOING = 0b10,
} conn_direction_t;

typedef enum {
    PACKET_COUNT_NONE = 0,
    PACKET_COUNT_ABSOLUTE = 1,
    PACKET_COUNT_INCREMENT = 2,
} packet_count_increment_t;

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
} conn_stats_ts_t;

// Connection flags
typedef enum {
    CONN_L_INIT = 1 << 0, // initial/first message sent
    CONN_R_INIT = 1 << 1, // reply received for initial message from remote
    CONN_ASSURED = 1 << 2 // "3-way handshake" complete, i.e. response to initial reply sent
} conn_flags_t;

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

typedef struct
{
    struct sock *sk;
    int segs;
    __u32 retrans_out_pre;
} tcp_retransmit_skb_args_t;

typedef struct
{
    __u32 netns;
    __u16 port;
} port_binding_t;

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
 * have the pid in the tcp_retransmit_skb().
 */
BPF_HASH_MAP(tcp_retransmits, conn_tuple_t, __u32, 1024)

/* Will hold the PIDs initiating TCP connections */
BPF_HASH_MAP(tcp_ongoing_connect_pid, struct sock *, __u64, 1024)

// We use this map as a container for batching closed tcp/udp connections
BPF_PERCPU_HASH_MAP(conn_close_batch, __u32, batch_t, 1024)

/* This is used for capturing state between the call and return of the tcp_retransmit_skb() system call.
 *
 * Keys: the PID returned by bpf_get_current_pid_tgid()
 * Values: the args of the tcp_retransmit_skb call being instrumented.
 */
BPF_HASH_MAP(pending_tcp_retransmit_skb, __u64, tcp_retransmit_skb_args_t, 8192)

/* This maps tracks listening TCP ports. Entries are added to the map via tracing the inet_csk_accept syscall.  The
 * key in the map is the network namespace inode together with the port and the value is a flag that
 * indicates if the port is listening or not. When the socket is destroyed (via tcp_v4_destroy_sock), we set the
 * value to be "port closed" to indicate that the port is no longer being listened on.  We leave the data in place
 * for the userspace side to read and clean up
 */
BPF_HASH_MAP(port_bindings, port_binding_t, __u32, 1024)

/* This behaves the same as port_bindings, except it tracks UDP ports.
 * Key: a port
 * Value: one of PORT_CLOSED, and PORT_OPEN
 */
BPF_HASH_MAP(udp_port_bindings, port_binding_t, __u32, 1024)

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} conn_close_event SEC(".maps");

static __always_inline void flush_conn_close_if_full(void *ctx) {
    u32 cpu = bpf_get_smp_processor_id();
    batch_t *batch_ptr = bpf_map_lookup_elem(&conn_close_batch, &cpu);
    if (!batch_ptr) {
        return;
    }

    if (batch_ptr->len == CONN_CLOSED_BATCH_SIZE) {
        bpf_printk("Flushing conn_close_batch\n");
        bpf_ringbuf_output(&conn_close_event, batch_ptr, sizeof(*batch_ptr), 0);
    }
}

static __always_inline int get_proto(conn_tuple_t *t) {
    return (t->metadata & CONN_TYPE_TCP) ? CONN_TYPE_TCP : CONN_TYPE_UDP;
}

static __always_inline void cleanup_conn(void *ctx, conn_tuple_t *tup, struct sock *sk) {
    u32 cpu = bpf_get_smp_processor_id();

    // Will hold the full connection data to send through the perf buffer
    conn_t conn = { .tup = *tup };
    conn_stats_ts_t *cst = NULL;
    tcp_stats_t *tst = NULL;
    u32 *retrans = NULL;
    bool is_tcp = get_proto(&conn.tup) == CONN_TYPE_TCP;
    bool is_udp = get_proto(&conn.tup) == CONN_TYPE_UDP;

    if (is_tcp) {
        tst = bpf_map_lookup_elem(&tcp_stats, &(conn.tup));
        if (tst) {
            conn.tcp_stats = *tst;
            bpf_map_delete_elem(&tcp_stats, &(conn.tup));
        }

        conn.tup.pid = 0;
        retrans = bpf_map_lookup_elem(&tcp_retransmits, &(conn.tup));
        if (retrans) {
            conn.tcp_retransmits = *retrans;
            bpf_map_delete_elem(&tcp_retransmits, &(conn.tup));
        }
        conn.tup.pid = tup->pid;

        conn.tcp_stats.state_transitions |= (1 << TCP_CLOSE);
    }

    cst = bpf_map_lookup_elem(&conn_stats, &(conn.tup));
    if (is_udp && !cst) {
        return; // nothing to report
    }
    if (is_tcp && !cst && !tst && !retrans) {
        return; // nothing to report
    }

    if (cst) {
        conn.conn_stats = *cst;
        bpf_map_delete_elem(&conn_stats, &(conn.tup));
    } else {
        // we don't have any stats for the connection,
        // so cookie is not set, set it here
        conn.conn_stats.cookie = bpf_get_prandom_u32();
    }

    conn.conn_stats.timestamp = bpf_ktime_get_ns();

    // Batch TCP closed connections before generating a perf event
    batch_t *batch_ptr = bpf_map_lookup_elem(&conn_close_batch, &cpu);
    if (batch_ptr == NULL) {
        return;
    }

    switch (batch_ptr->len) {
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

static __always_inline void handle_tcp_stats(conn_tuple_t *t, struct sock *sk, u8 state) {
    u32 rtt = 0, rtt_var = 0;
    BPF_CORE_READ_INTO(&rtt, tcp_sk(sk), srtt_us);
    BPF_CORE_READ_INTO(&rtt_var, tcp_sk(sk), mdev_us);

    tcp_stats_t stats = { .rtt = rtt, .rtt_var = rtt_var };
    if (state > 0) {
        stats.state_transitions = (1 << state);
    }
    update_tcp_stats(t, stats);
}

static __always_inline conn_stats_ts_t *get_conn_stats(conn_tuple_t *t, struct sock *sk) {
    conn_stats_ts_t *cs = bpf_map_lookup_elem(&conn_stats, t);
    if (cs) {
        return cs;
    }

    // initialize-if-no-exist the connection stat, and load it
    conn_stats_ts_t empty = {};
    empty.cookie = get_sk_cookie(sk);
    bpf_map_update_elem(&conn_stats, t, &empty, BPF_NOEXIST);
    return bpf_map_lookup_elem(&conn_stats, t);
}

/**
 * Updates the connection state flags based on the number of bytes sent and received.
 */
static __always_inline void update_conn_state(conn_tuple_t *t, conn_stats_ts_t *stats, size_t sent_bytes, size_t recv_bytes) {
    if (t->metadata & CONN_TYPE_TCP || stats->flags & CONN_ASSURED) {
        return;
    }

    // If the connection is not yet initialized, we set the appropriate flag based on the direction of the first packet
    if (stats->recv_bytes == 0 && sent_bytes > 0) {
        stats->flags |= CONN_L_INIT;
        return;
    }

    // If the connection is not yet initialized, we set the appropriate flag based on the direction of the first packet
    if (stats->sent_bytes == 0 && recv_bytes > 0) {
        stats->flags |= CONN_R_INIT;
        return;
    }

    // If a three-way "handshake" was established, we mark the connection as assured
    if ((stats->flags & CONN_L_INIT && stats->recv_bytes > 0 && sent_bytes > 0) || (stats->flags & CONN_R_INIT && stats->sent_bytes > 0 && recv_bytes > 0)) {
        stats->flags |= CONN_ASSURED;
    }
}

/**
 * Updates the connection metadata with the given parameters.
 * This includes the protocol, tags, timestamp, direction, packets, and bytes sent and received.
 * If the connection is not found in the map, this function does nothing.
 *
 * @param t The connection tuple.
 * @param sent_bytes The number of bytes sent.
 * @param recv_bytes The number of bytes received.
 * @param ts The timestamp.
 * @param dir The direction of the connection.
 * @param packets_out The number of packets sent.
 * @param packets_in The number of packets received.
 * @param segs_type The type of packet count increment.
 * @param sk The socket struct.
 */
static __always_inline void update_conn_stats(conn_tuple_t *t, size_t sent_bytes, size_t recv_bytes, u64 ts, conn_direction_t dir,
    __u32 packets_out, __u32 packets_in, packet_count_increment_t segs_type, struct sock *sk) {
    conn_stats_ts_t *val = NULL;
    val = get_conn_stats(t, sk);
    if (!val) {
        return;
    }

    // If already in our map, increment size in-place
    update_conn_state(t, val, sent_bytes, recv_bytes);
    if (sent_bytes) {
        __sync_fetch_and_add(&val->sent_bytes, sent_bytes);
    }
    if (recv_bytes) {
        __sync_fetch_and_add(&val->recv_bytes, recv_bytes);
    }
    if (packets_in) {
        if (segs_type == PACKET_COUNT_INCREMENT) {
            __sync_fetch_and_add(&val->recv_packets, packets_in);
        } else if (segs_type == PACKET_COUNT_ABSOLUTE) {
            val->recv_packets = packets_in;
        }
    }
    if (packets_out) {
        if (segs_type == PACKET_COUNT_INCREMENT) {
            __sync_fetch_and_add(&val->sent_packets, packets_out);
        } else if (segs_type == PACKET_COUNT_ABSOLUTE) {
            val->sent_packets = packets_out;
        }
    }
    val->timestamp = ts;

    if (dir != CONN_DIRECTION_UNKNOWN) {
        val->direction = dir;
    } else if (val->direction == CONN_DIRECTION_UNKNOWN) {
        u32 *port_count = NULL;
        port_binding_t pb = {};
        pb.port = t->sport;
        pb.netns = t->netns;
        if (t->metadata & CONN_TYPE_TCP) {
            port_count = bpf_map_lookup_elem(&port_bindings, &pb);
        } else {
            port_count = bpf_map_lookup_elem(&udp_port_bindings, &pb);
        }
        val->direction = (port_count != NULL && *port_count > 0) ? CONN_DIRECTION_INCOMING : CONN_DIRECTION_OUTGOING;
    }
}

/**
 * This function updates connection statistics for a given connection tuple and direction.
 * It takes in the connection tuple, the number of bytes sent and received, the direction of the connection,
 * the number of packets sent and received, the type of packet count increment, and the socket structure.
 * It then updates the connection statistics for the given connection tuple and direction.
 * @param t The connection tuple for which to update statistics.
 * @param sent_bytes The number of bytes sent.
 * @param recv_bytes The number of bytes received.
 * @param dir The direction of the connection.
 * @param packets_out The number of packets sent.
 * @param packets_in The number of packets received.
 * @param segs_type The type of packet count increment.
 * @param sk The socket structure.
 * @return 0 on success.
 */
static __always_inline int handle_message(conn_tuple_t *t, size_t sent_bytes, size_t recv_bytes, conn_direction_t dir,
    __u32 packets_out, __u32 packets_in, packet_count_increment_t segs_type, struct sock *sk) {
    u64 ts = bpf_ktime_get_ns();
    update_conn_stats(t, sent_bytes, recv_bytes, ts, dir, packets_out, packets_in, segs_type, sk);
    return 0;
}

// Reads the number of incoming and outgoing TCP segments for a given socket.
static __always_inline void get_tcp_segment_counts(struct sock *skp, __u32 *packets_in, __u32 *packets_out) {
    BPF_CORE_READ_INTO(packets_out, tcp_sk(skp), segs_out);
    BPF_CORE_READ_INTO(packets_in, tcp_sk(skp), segs_in);
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
