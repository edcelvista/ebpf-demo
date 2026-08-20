# eBPF Hello World with GoLang
[ebpf.io](https://ebpf.io)

## Requirements:
1. **Install** Linux VM _(via multipass)_ - _required for linux headers_
2. **Install** the required packages.
    ```
    - net-tools
    - golang-go
    - clang
    - llvm
    - linux-libc-dev
    - linux-tools-common
    - linux-tools-generic
    - libbpf-dev
    - linux-lowlatency-tools-common
    - build-essential
    - python3
    - python3-pip
    - python3-venv
    ```
    2a. Provision and boostrap the Workspace VM.
    ```
    ./_setup.sh
    ```

## Compile eBPF & Go Program
1. **SSH** to the virtual environment
    ```
    multipass shell ebpf-working-environment1
    ```
2. **Compile** eBPF Program _(Kernel Space)_
    ```
    cd /mnt/workspace/bpf
    make clean && make
    ```
3.  **Compile** Go Program
    ```
    cd /mnt/workspace/cmd
    make clean && make init && make build
    ```
4. **Run** the Program
    ```
    sudo ./helloworld
    ```

## Trigger kernel syscall `do_sys_openat2`
**Run:** `cat /etc/hosts` (this triggers `do_sys_openat2`)

## Response
```
2026/08/20 00:25:41 eBPF program loaded
2026/08/20 00:25:41 waiting for events...
2026/08/20 00:25:41 EVENT: Hello, eBPF! <--- response from syscall event
```

### What happened? 
Every kernel syscall `do_sys_openat2()` a hook triggers a `hello()` function which sends event message to userspace which then reads by Go Program.

## Kernel to Userspace Structure
```
 Linux kernel
      │
      │ do_sys_openat2()
      ▼
 ┌──────────────┐
 │ eBPF program │
 │    hello()   │
 └──────┬───────┘
        │
        │ event
        ▼
 ┌──────────────┐
 │ Ring Buffer  │
 └──────┬───────┘
        │
        │ userspace reads / rd.Read() in go userspace
        ▼
 ┌──────────────┐
 │ Go program   │
 └──────────────┘

 eBPF kernel                        Go
    │                               │
    │       ring buffer             │
    │  ┌───────────────────────┐    │
    ├─►│ event │ event │ event │───►│
    │  └───────────────────────┘    │
    │                               │
    └── produce                  consume
```

## Trigger Flow
```
 cat
  │
  │ open()
  ▼
 Linux kernel
  │
  ▼
 do_sys_openat2()
  │
  │ kprobe fires
  ▼
 hello()
  │
  ├── reserve 32 bytes
  │
  ├── write "Hello, eBPF!"
  │
  └── submit event
  │
  ▼
 BPF ring buffer
  │
  │ Go reads
  ▼
 Go userspace
  │
  ▼
 EVENT: Hello, eBPF! <------ log.Printf()
```

## The three most important pieces
### Kernel eBPF: `C Code`
```
bpf_ringbuf_submit(e, 0);
```

### Go ring-buffer reader:
```
record, err := rd.Read()
```

### Go event decoder:
```
record, err := rd.Read()
binary.Read(..., &event)
```
```
KERNEL                 USERSPACE
bpf_ringbuf_submit()
	│
	▼
Ring buffer
	│
	│
	└──────────────► rd.Read()
							│
							▼
						record
```

# Networ Tracer _(sample use-case)_
Bind to Kernel `tracepoint/sock/inet_sock_set_state` and capture each connection states and calculate latency.

```
$ curl https://httpbin.org/delay/5
{
  "args": {},
  "data": "",
  "files": {},
  "form": {},
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.org",
    "User-Agent": "curl/8.5.0",
    "X-Amzn-Trace-Id": "Root=1-6a874c53-0e5eb31966c8529914d35afe"
  },
  "origin": "110.93.89.24",
  "url": "https://httpbin.org/delay/5"
}
```

```
2026/08/21 02:49:53 eBPF NET tracer running...
PID=12200 192.168.252.96:0 -> 3.210.29.144:443  CLOSE -> SYN_SENT latency=0.000005s
PID=12200 192.168.252.96:43390 -> 3.210.29.144:443  SYN_SENT -> ESTABLISHED latency=0.216879s
PID=12200 192.168.252.96:43390 -> 3.210.29.144:443  ESTABLISHED -> FIN_WAIT1 latency=5.963027s
PID=12200 192.168.252.96:43390 -> 3.210.29.144:443  FIN_WAIT1 -> CLOSING latency=6.173842s
PID=12200 192.168.252.96:43390 -> 3.210.29.144:443  CLOSING -> CLOSE latency=6.179207s
```