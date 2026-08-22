package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

var syscallNames = map[uint64]string{
	56: "openat",
	57: "close",
	58: "vhangup",
	59: "pipe2",
	61: "getdents64",
	62: "lseek",
	63: "read",
	64: "write",
	65: "readv",
	66: "writev",
	67: "pread64",
	68: "pwrite64",
	69: "preadv",
	70: "pwritev",
	71: "sendfile",
	72: "pselect6",
	73: "ppoll",
	74: "signalfd4",
	75: "vmsplice",
	76: "splice",
	77: "tee",
	78: "readlinkat",
	79: "fstatat",
	80: "fstat",
	81: "sync",
	82: "fsync",
	83: "fdatasync",
	84: "sync_file_range",

	93:  "exit",
	94:  "exit_group",
	95:  "waitid",
	96:  "set_tid_address",
	97:  "unshare",
	98:  "futex",
	99:  "set_robust_list",
	100: "get_robust_list",
	101: "nanosleep",

	117: "ptrace",

	129: "kill",
	130: "tkill",
	131: "tgkill",

	160: "uname",
	163: "getrlimit",
	164: "setrlimit",
	165: "getrusage",
	166: "umask",
	167: "prctl",
	168: "getcpu",
	169: "gettimeofday",
	172: "getpid",
	173: "getppid",
	174: "getuid",
	175: "geteuid",
	176: "getgid",
	177: "getegid",
	178: "gettid",

	198: "socket",
	199: "socketpair",
	200: "bind",
	201: "listen",
	202: "accept",
	203: "connect",
	204: "getsockname",
	205: "getpeername",
	206: "sendto",
	207: "recvfrom",
	208: "setsockopt",
	209: "getsockopt",
	210: "shutdown",
	211: "sendmsg",
	212: "recvmsg",

	214: "brk",
	215: "munmap",
	216: "mremap",

	220: "clone",
	221: "execve",
	222: "mmap",

	228: "msync",
	229: "mlock",
	230: "munlock",
	231: "mlockall",
	232: "munlockall",
	233: "mincore",
	234: "madvise",

	240: "rt_tgsigqueueinfo",
	241: "perf_event_open",
	242: "accept4",
	243: "recvmmsg",

	260: "wait4",
	261: "prlimit64",
	262: "fanotify_init",
	263: "fanotify_mark",

	278: "getrandom",
	280: "memfd_create",
	281: "bpf",
	291: "statx",
}

type Event struct { // This must correspond to your C structure: event
	TimestampNs uint64
	PID         uint32
	SyscallID   uint64
	Comm        string

	Cwd string // user-space
	Cmd string // user-space
}

func main() {
	// Load generated BPF objects. by go generate
	objs := systraceObjects{}
	if err := loadSystraceObjects(&objs, nil); err != nil {
		log.Fatalf("loading BPF objects: %v", err)
	}
	defer objs.Close()

	var pid int
	fmt.Print("Enter PID: ")
	if _, err := fmt.Scan(&pid); err != nil {
		log.Fatalf("invalid PID: %v", err)
	}
	fmt.Printf("Tracing PID %d\n", pid)

	if pidExists(pid) {
		fmt.Printf("PID %d exists\n", pid)
	} else {
		fmt.Printf("PID %d does not exist\n", pid)
	}

	// Pass data to kernel space via maps
	var key uint32 = 0
	var upid uint32 = uint32(pid) // TODO CHECK if necesary
	if err := objs.TargetPid.Put(key, upid); err != nil {
		log.Fatalf("setting target PID: %v", err)
	}

	/* Attach:
	SEC("raw_tracepoint/sys_enter")
	*/
	tp, err := link.AttachRawTracepoint(
		link.RawTracepointOptions{
			Name:    "sys_enter",
			Program: objs.TraceSysEnter,
		},
	)
	if err != nil {
		log.Fatalf("attaching tracepoint: %v", err)
	}
	defer tp.Close()

	log.Println("eBPF SYS TRACER Running...")

	// Read the BPF ring buffer.
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("creating ringbuf reader: %v", err)
	}
	defer reader.Close()

	/*
		                    Main goroutine
									│
									▼
							reader.Read()
									│
									│ blocked
									│
			Ctrl+C                  │
			│                       │
			▼                       │
			SIGINT                  │
			│                       │
			▼                       │
			signal goroutine        │
			│                       │
			▼                       │
			reader.Close() ──────────┘
									│
									▼
								Read() returns
	*/

	// Handle Ctrl-C.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM) // Whenever the process receives SIGINT or SIGTERM, send it to the sig channel.
	defer signal.Stop(sig)
	go func() {
		<-sig // Wait until something is received from the sig channel.

		/*
		 * Closing the ring buffer wakes Read().
		 */

		_ = reader.Close() // no return required, reader.close() naturally stop the main thread
	}()

	// Handle PID Exits.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if !pidExists(pid) {
					_ = reader.Close()
					return
				}
			case <-ctx.Done(): // clean go routine once main thread exits
				return
			}
		}
	}()

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				break // closed reader as shutdown condition
			}

			/*
			 * Don't continuously retry a closed reader.
			 */
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Printf("reading ringbuf: %v", err)
			continue
		}

		var event Event
		// Decode directly from RawSample removes bytes.NewReader() and binary.Read() from the equation.
		event.TimestampNs = binary.LittleEndian.Uint64(record.RawSample[0:8])
		event.PID = binary.LittleEndian.Uint32(record.RawSample[8:12])
		event.SyscallID = binary.LittleEndian.Uint64(record.RawSample[16:24])
		event.Comm = string(record.RawSample[24:26])

		cwd, cmd := getPIDCWD_CMD(event.PID)
		event.Cwd = cwd
		event.Cmd = cmd

		name, ok := syscallNames[event.SyscallID]
		if !ok {
			name = fmt.Sprintf("unknown(%d)", event.SyscallID)
		}

		fmt.Printf(
			"%d PID=%d COMM=%s CWD=%s CMD=%s SYS_CALL=%s SYS_CALL_ID=%d\n",
			event.TimestampNs,
			event.PID,
			event.Comm,
			event.Cwd,
			event.Cmd,
			name,
			event.SyscallID,
		)
	}
}

func pidExists(pid int) bool {
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	if errors.Is(err, syscall.EPERM) {
		// Process exists, but we don't have permission.
		return true
	}
	if errors.Is(err, syscall.ESRCH) {
		// No such process.
		return false
	}
	return false
}

func getPIDCWD_CMD(PID uint32) (string, string) {
	cwd, _ := os.Readlink(
		fmt.Sprintf("/proc/%d/cwd", PID),
	)

	cmdline, err := os.ReadFile(
		fmt.Sprintf("/proc/%d/cmdline", PID),
	)
	if err != nil {
		cmdline = nil
	}
	cmd := strings.ReplaceAll(string(cmdline), "\x00", " ")
	cmd = strings.TrimSpace(cmd)

	return cwd, cmd
}
