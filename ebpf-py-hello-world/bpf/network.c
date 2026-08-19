#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

int tcpconnect(void *ctx){
    bpf_trace_printk("[tcpconnect]\n");
    return 0;
}