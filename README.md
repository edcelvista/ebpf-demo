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

# Real-world Applications

## Network Tracer
Bind to Kernel `tracepoint/sock/inet_sock_set_state` and capture each connection states and calculate latency.

### Network Call (via curl)
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
    "X-Amzn-Trace-Id": "Root=1-6a944381-2bd25f303829a6cc75d7c0f1"
  }, 
  "origin": "13.63.92.146", 
  "url": "https://httpbin.org/delay/5"
}
```

### eBPF Trace Response
```
2026/08/30 14:51:40 eBPF NET TRACER Running...
40885860438216 PID=67331 COMM=curl CWD=/apps/workspace CMD=curl https://httpbin.org/delay/5 CONN=172.31.36.100:0->34.195.135.204:443[CLOSE]->[SYN_SENT] LATENCY=0.000005s
40885971493883 PID=67331 COMM=swapper/1 CWD=/apps/workspace CMD=curl https://httpbin.org/delay/5 CONN=172.31.36.100:59690->34.195.135.204:443[SYN_SENT]->[ESTABLISHED] LATENCY=0.111060s
40891598247263 PID=67331 COMM=curl CWD=/apps/workspace CMD=curl https://httpbin.org/delay/5 CONN=172.31.36.100:59690->34.195.135.204:443[ESTABLISHED]->[FIN_WAIT1] LATENCY=5.737814s
40891708413452 PID=67331 COMM=swapper/0 CWD= CMD= CONN=172.31.36.100:59690->34.195.135.204:443[FIN_WAIT1]->[CLOSING] LATENCY=5.847980s
40891709178451 PID=67331 COMM=swapper/0 CWD= CMD= CONN=172.31.36.100:59690->34.195.135.204:443[CLOSING]->[CLOSE] LATENCY=5.848745s
```
Note: It shows Latency between syscall eg. `[FIN_WAIT1]` it waits around 5s.

## System Call Tracer
Detect all system call entry by tapping from `raw_tracepoint/sys_enter`.
_Example C Program that invokes couple of kernel syscalls_
[systrace-test.c](./ebpf-go-hello-world/bpf/systrace-test/systrace-test.c)
```
make build && ./systrace-test /etc/passwd # shows pid 84199
```

### eBPF Trace Response
```
Enter PID: 84199
Tracing PID 84199
PID 84199 exists
2026/08/30 15:56:03 eBPF SYS TRACER Running...
44745163818002 PID=84199 COMM=sy CWD=/apps/workspace/ebpf-demo/ebpf-go-hello-world/bpf/systrace-test CMD=./systrace-test /etc/passwd SYS_CALL=openat SYS_CALL_ID=257
44745163856479 PID=84199 COMM=sy CWD=/apps/workspace/ebpf-demo/ebpf-go-hello-world/bpf/systrace-test CMD=./systrace-test /etc/passwd SYS_CALL=write SYS_CALL_ID=1
44745163872943 PID=84199 COMM=sy CWD=/apps/workspace/ebpf-demo/ebpf-go-hello-world/bpf/systrace-test CMD=./systrace-test /etc/passwd SYS_CALL=fstat SYS_CALL_ID=5
44745163877868 PID=84199 COMM=sy CWD=/apps/workspace/ebpf-demo/ebpf-go-hello-world/bpf/systrace-test CMD=./systrace-test /etc/passwd SYS_CALL=write SYS_CALL_ID=1
44745163895847 PID=84199 COMM=sy CWD=/apps/workspace/ebpf-demo/ebpf-go-hello-world/bpf/systrace-test CMD=./systrace-test /etc/passwd SYS_CALL=read SYS_CALL_ID=0
44745163901454 PID=84199 COMM=sy CWD=/apps/workspace/ebpf-demo/ebpf-go-hello-world/bpf/systrace-test CMD=./systrace-test /etc/passwd SYS_CALL=close SYS_CALL_ID=3
44745163906780 PID=84199 COMM=sy CWD=/apps/workspace/ebpf-demo/ebpf-go-hello-world/bpf/systrace-test CMD=./systrace-test /etc/passwd SYS_CALL=clock_nanosleep SYS_CALL_ID=230
```
It shows the list of syscall made by the running program eg. `read()` `clock_nanosleep()`

## Malloc Tracer
Bind `uprobe/malloc` which detects when userspace allocate memory via `malloc()`
_Example C Program that allocates memory via malloc_
[malloc-test.c](./ebpf-go-hello-world/bpf/malloc-test/malloc-test.c)
```
./malloc-test 10496000
PID: 88199
Allocated: 10496000 bytes (10.01 MiB)
```

### eBPF Trace Response
```
eBPF Program=trace_malloc Section=uprobe/malloc
Arch: amd64 | libcPath: /lib/x86_64-linux-gnu/libc.so.6
45251111664393 PID=88199 COMM=malloc-test CWD=/apps/workspace/ebpf-demo/ebpf-go-hello-world/bpf/malloc-test CMD=./malloc-test 10496000 SID=18446744073709551599 TGID=88199 UID=1000 SIZE=malloc: 10496000 bytes: (10.01 MB)
```

The trace shows the exact amount of memory allocated and who allocated it including the PID Command.


**References:**
- https://manual.cs50.io/
- https://docs.ebpf.io/ebpf-library/libbpf/ebpf/BPF_CORE_READ/
- https://github.com/cilium/ebpf
- https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md
- https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
- https://elixir.bootlin.com/linux/v7.2/source/tools/testing/selftests/bpf
- https://100go.co/#error-management