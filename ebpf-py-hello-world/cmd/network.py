from bcc import BPF

interface="eth0"

b = BPF(src_file="bpf/network.c")
b.attach_kprobe(event="tcp_v4_connect", fn_name="tcpconnect")

print("Loaded.")

try:
    b.trace_print()
except KeyboardInterrupt:
    print("\n unloading")
