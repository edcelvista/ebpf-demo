#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct malloc_event {
    u64 timestamp_ns;
    u64 size;
    u64 stack_id;
    u32 pid;       // Thread ID
    u32 tgid;      // Process ID
    u32 uid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u64[127]); // 127 arbitrary size of the bpf stack trace map 127 × 8 bytes = 1016 bytes
} stacks SEC(".maps");

// Attach to the 'malloc' function in any process
SEC("uprobe/malloc")
int trace_malloc(struct pt_regs *ctx) {
    u64 size = PT_REGS_PARM1(ctx); // similar as (((const struct user_pt_regs *)(ctx))->regs[0])
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;       // Process ID
    u32 pid  = (u32)pid_tgid;        // Thread ID

    struct malloc_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->size = size;
    e->stack_id = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK);
    e->pid = pid;
    e->tgid = tgid;
    e->uid = (u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // [DEBUG] sudo cat /sys/kernel/debug/tracing/trace_pipe
    // bpf_printk(
    //     "pid=%u comm=%u",
    //     e->pid,
    //     e->comm
    // );

    bpf_ringbuf_submit(e, 0);

    return 0;
}