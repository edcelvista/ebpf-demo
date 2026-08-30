#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
    offset
    0       4       8                16               32
    │       │       │                │                │
    ├───────┤       ├────────────────┤                │
    │ PID   │ pad   │   syscall_id   │    comm        │
    │ 4     │ 4     │      8         │    16          │
    └───────┴───────┴────────────────┴────────────────┘

    event.PID = binary.LittleEndian.Uint32(record.RawSample[0:4])
    event.SyscallID = binary.LittleEndian.Uint64(record.RawSample[8:16])
    record.RawSample[16:32]
*/
struct event {
    __u64 timestamp_ns;
    __u32 pid;
    __u64 syscall_id;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF); 
    __uint(max_entries, 1 << 24); 
} events SEC(".maps"); 

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pid SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx){
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&target_pid, &key);
    if (!target)
        return 0;

    __u32 target_pid_value = *target;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (target_pid_value != 0 && pid != target_pid_value)
        return 0;

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;


    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid;

    /*
        * raw sys_enter:
        * args[1] = syscall number
    */
    e->syscall_id = ctx->args[1];
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);

    return 0;
}