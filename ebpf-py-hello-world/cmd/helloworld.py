from bcc import BPF

b = BPF(src_file="bpf/helloworld.c")
# b.attach_kprobe(event="__x64_sys_execve", fn_name="hello")
b.attach_kprobe(event="__arm64_sys_execve", fn_name="hello")


print("Loaded.")

try:
    b.trace_print()
except KeyboardInterrupt:
    print("\n unloading")
