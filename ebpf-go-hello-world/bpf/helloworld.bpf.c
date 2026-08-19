#include "vmlinux.h" // bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct event {
    char message[32];
};

// event
// └── message
//     └── 32 bytes
// +--------------------------------+
// | H e l l o ,   e B P F ! \0 ... |
// +--------------------------------+
//              32 bytes

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF); // A ring buffer (BPF_MAP_TYPE_RINGBUF) is a way for kernel eBPF programs to send data to userspace.
    __uint(max_entries, 1 << 24); // max size 16,777,216 or 16 MiB
} events SEC(".maps"); // tells Clang Put this map definition into the ELF .maps section.

// .maps
//  └── events
//        └── BPF_MAP_TYPE_RINGBUF

SEC("kprobe/do_sys_openat2") // This eBPF program is intended to be attached as a kprobe to do_sys_openat2. When kernel executes do_sys_openat2(), hello() runs
int hello(void *ctx)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0); // Give me enough space in the events ring buffer to store one struct event.
    if (!e) //  Check if reservation failed
        return 0;

    __builtin_memcpy(e->message, "Hello, eBPF!", 13); // Put the message into the event | 12 characters + 1 null terminator = 13 bytes

    bpf_ringbuf_submit(e, 0); // . Submit the event

    return 0;
}
