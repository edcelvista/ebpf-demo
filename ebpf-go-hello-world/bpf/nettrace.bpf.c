#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2
#define TCP_SYN_RECV    3
#define TCP_FIN_WAIT1   4
#define TCP_FIN_WAIT2   5
#define TCP_TIME_WAIT   6
#define TCP_CLOSE       7
#define TCP_CLOSE_WAIT  8
#define TCP_LAST_ACK    9
#define TCP_LISTEN      10
#define TCP_CLOSING     11

struct conn_key {
    __u64 sock_ptr;
};

struct conn_info {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 pid;
    __u32 tgid;
    __u64 start_ns;
};

struct tcp_event {
    __u64 timestamp_ns;
    __u64 latency_ns;

    __u32 pid;
    __u32 tgid;

    __u32 saddr;
    __u32 daddr;

    __u16 sport;
    __u16 dport;

    __u8 oldstate;
    __u8 newstate;
    __u16 family;

    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); // the map also protects you from unlimited stale entries:, If something goes wrong and a TCP_CLOSE cleanup is missed, the LRU mechanism can eventually evict old entries.
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct conn_info);
} connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline void
read_conn_info(struct sock *sk, struct conn_info *info) {
    info->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    info->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    info->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    info->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    /*
        63                         32 31                          0
        +----------------------------+----------------------------+
        |            TGID            |             PID            |
        +----------------------------+----------------------------+
                    32 bits                    32 bits
    */

    info->pid = bpf_get_current_pid_tgid() >> 32;
    info->tgid = bpf_get_current_pid_tgid() & 0xffffffff;
    info->start_ns = bpf_ktime_get_ns();
    
    // [DEBUG]
    // bpf_printk(
    //     "fill: sk=%p saddr=%x daddr=%x sport=%u dport=%u",
    //     sk,
    //     info->saddr,
    //     info->daddr,
    //     info->sport,
    //     info->dport
    // );
}

SEC("tracepoint/sock/inet_sock_set_state")
int trace_tcp_state(struct trace_event_raw_inet_sock_set_state *ctx){
    struct sock *sk = (struct sock *)ctx->skaddr; // Received Kernen Event Message and store into sock struct provided by vmlinux library
    if (!sk)
        return 0;

    /* If IP Address return 0.0.0.0:0
        Some info are not populated yet - and get populated as state increases.

        state=2  saddr=60fca8c0 daddr=2ec5fa8e sport=0     dport=20480
        state=1  saddr=60fca8c0 daddr=2ec5fa8e sport=49530 dport=20480
        state=4  saddr=60fca8c0 daddr=2ec5fa8e sport=49530 dport=20480
        state=5  saddr=60fca8c0 daddr=2ec5fa8e sport=49530 dport=20480
        state=7  saddr=60fca8c0 daddr=2ec5fa8e sport=0     dport=20480

        LINUX TCP
            2 = TCP_SYN_SENT
            1 = TCP_ESTABLISHED
            4 = TCP_FIN_WAIT1
            5 = TCP_FIN_WAIT2
            7 = TCP_CLOSE

            SYN_SENT
                │
                │ local port not assigned/readable yet
                ▼
            ESTABLISHED
                │
                │ 49530 -> 20480
                ▼
            FIN_WAIT1
                ▼
            FIN_WAIT2
                │
                │ local port becomes 0
                ▼
            CLOSE  
    */

    // [DEBUG] sudo cat /sys/kernel/debug/tracing/trace_pipe
    // __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    // __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    // __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    // __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    // __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    // bpf_printk(
    //     "family=%u state=%u sk=%p saddr=%x daddr=%x sport=%u dport=%u",
    //     family,
    //     ctx->newstate,
    //     sk,
    //     saddr,
    //     daddr,
    //     sport,
    //     dport
    // );

    /*
     * We only care about TCP.
    */

    // if (ctx->protocol != IPPROTO_TCP)
    //     return 0;

    // /*
    //  * New state must be ESTABLISHED.
    // */

    // if (ctx->newstate != TCP_ESTABLISHED)
    //     return 0;

    __u64 key = (__u64)sk; // gives a numeric representation of the socket pointer and use it as map key as connection identity
    struct conn_info *cached;

    /*
        connections
        ┌──────────────┬──────────────────────┐
        │ key          │ value                │
        ├──────────────┼──────────────────────┤
        │ 100          │ connection_info {...}│
        │ 200          │ connection_info {...}│
        │ 300          │ connection_info {...}│
        └──────────────┴──────────────────────┘

        connections
                key                         value
        ┌─────────────────────┐    ┌──────────────────────┐
        │ __u64 socket address│ -> │ struct conn_info     │
        └─────────────────────┘    └──────────────────────┘

        __u64 key = 100;
        bpf_map_lookup_elem(&connections, &key);
        "Does the connections map contain key 100?"

        Returns
        pointer to value  → found
        NULL              → not found
    */

    cached = bpf_map_lookup_elem(&connections, &key);
    struct conn_info current = {};

    /*
     * Read the current socket tuple.
    */

    read_conn_info(sk, &current);

    /*
     * If we already have a valid tuple, preserve it.
     *
     * This is important because Linux can clear fields such as
     * skc_num during the later TCP_CLOSE transition.
    */

    if (cached) {
        if (current.saddr == 0)
            current.saddr = cached->saddr;

        if (current.daddr == 0)
            current.daddr = cached->daddr;

        if (current.sport == 0)
            current.sport = cached->sport;

        if (current.dport == 0)
            current.dport = cached->dport;

        current.pid = cached->pid;
        current.tgid = cached->tgid;
        current.start_ns = cached->start_ns;
    }

    /*
     * Save the tuple for future state transitions.
    */

    if (current.saddr != 0 || current.daddr != 0 || current.sport != 0 || current.dport != 0) {
        /*
            connections
            0xffff888012345600
                    │
                    ▼
            ┌───────────────────────────┐
            │ saddr = 192.168.1.10      │
            │ daddr = 142.250.x.x       │
            │ sport = 49530             │
            │ dport = 443               │
            │ pid   = 1234              │
            │ tgid  = 1234              │
            │ start = 123456789         │
            └───────────────────────────┘

            BPF_ANY => Insert the entry if it doesn’t exist, or replace it if it already exists.
        */

        bpf_map_update_elem(&connections, &key, &current, BPF_ANY); // Store current in the BPF map connections, using key as the identifier.
    }

    /*
     * Emit EVERY TCP state transition.
    */

    struct tcp_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0); // Reserve a piece of space in the BPF ring buffer where the eBPF program can write one event.
    if (event){
        event->timestamp_ns = bpf_ktime_get_ns();
        if (current.start_ns)
            event->latency_ns = event->timestamp_ns - current.start_ns;
        else
            event->latency_ns = 0;

        event->pid = current.pid;
        event->tgid = current.tgid;
        event->saddr = current.saddr;
        event->daddr = current.daddr;
        event->sport = current.sport;
        event->dport = current.dport;
        event->oldstate = ctx->oldstate;
        event->newstate = ctx->newstate;
        event->family = BPF_CORE_READ(sk, __sk_common.skc_family);
        bpf_get_current_comm(event->comm, sizeof(event->comm));

        bpf_ringbuf_submit(event, 0);
    }

    /*
     * Once CLOSE is reached, this socket's lifecycle is finished.
    */
   
    if (ctx->newstate == TCP_CLOSE)
        bpf_map_delete_elem(&connections, &key);

    return 0;
}