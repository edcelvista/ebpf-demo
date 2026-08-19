int hello(void *ctx) {
    bpf_trace_printk("Hello\\n");
    return 0;
}