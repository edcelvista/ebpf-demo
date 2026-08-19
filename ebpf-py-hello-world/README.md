# eBPF Hello World!
[ebpf.io](https://ebpf.io)

## Requirements:
1. **Install** Linux VM _(via multipass)_
2. **Install** the required packages.
    ```
    - clang
    - llvm
    - linux-libc-dev
    - linux-tools-common
    - linux-tools-generic
    - build-essential
    - python3
    - python3-pip
    - python3-venv
    ```
    ```
    ./_setup.sh
    ```

## Run eBPF Program
1. **SSH** to the virtual environment
    ```
    multipass shell ebpf-working-environment1
    ```
2. **Load & Run **eBPF Program
    ```
    /mnt/project$ sudo python3 cmd/helloworld.py
    ```
## Trigger kernel syscall `execve`
**Run:** `ls` (this `triggers __arm64_sys_execve` or `__x64_sys_execve`)

## Response
```
b'            bash-8114    [000] d..21   361.692357: bpf_trace_printk: Hello\\n'
```

### Breakdown
| Part | Meaning |
|---|---|
b'...' | Python bytes representation
bash | Process that triggered your eBPF program
8114 | PID of the bash process
[000] | CPU/core where the event occurred
d..21 | Kernel tracing flags
361.692357 | Timestamp, seconds since system boot
bpf_trace_printk | BPF helper that produced the message
Hello\n | Message from your eBPF program

```
bash (PID 8114)
      │
      │ kernel event
      ▼
┌─────────────────────┐
│ Linux kernel        │
│                     │
│  kprobe/tracepoint  │
│         │           │
│         ▼           │
│    hello() BPF      │
│         │           │
│         ▼           │
│ bpf_trace_printk()  │
└─────────┬───────────┘
          │
          ▼
     trace_pipe
          │
          ▼
       BCC Python
          │
          ▼
b'... Hello\n'
```

```
bash
  │
  └── execve("/usr/bin/ls")
          │
          ▼
    sys_enter_execve
          │
          ▼
       hello()
          │
          ▼
    "Hello\n"
```

---

## Trace Network Events
1. **SSH** to the virtual environment
    ```
    multipass shell ebpf-working-environment1
    ```
2. **Load & Run **eBPF Program
    ```
    /mnt/project$ sudo python3 cmd/network.py
    ```

## Trigger kernel syscall `tcp_v4_connect`
**Run:** `nc -v 192.168.252.94 22` (this `triggers tcp_v4_connect`)
```
nc -v 192.168.252.94 22
Connection to 192.168.252.94 22 port [tcp/ssh] succeeded!
SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18
```

## Response
```
b'              nc-8437    [000] d..21  1728.356914: bpf_trace_printk: [tcpconnect]'
```