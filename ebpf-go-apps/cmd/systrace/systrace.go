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
	0:   "read",
	1:   "write",
	2:   "open",
	3:   "close",
	4:   "stat",
	5:   "fstat",
	6:   "lstat",
	7:   "poll",
	8:   "lseek",
	9:   "mmap",
	10:  "mprotect",
	11:  "munmap",
	12:  "brk",
	13:  "rt_sigaction",
	14:  "rt_sigprocmask",
	15:  "rt_sigreturn",
	16:  "ioctl",
	17:  "pread64",
	18:  "pwrite64",
	19:  "readv",
	20:  "writev",
	21:  "access",
	22:  "pipe",
	23:  "select",
	24:  "sched_yield",
	25:  "mremap",
	26:  "msync",
	27:  "mincore",
	28:  "madvise",
	29:  "shmget",
	30:  "shmat",
	31:  "shmctl",
	32:  "dup",
	33:  "dup2",
	34:  "pause",
	35:  "nanosleep",
	36:  "getitimer",
	37:  "alarm",
	38:  "setitimer",
	39:  "getpid",
	40:  "sendfile",
	41:  "socket",
	42:  "connect",
	43:  "accept",
	44:  "sendto",
	45:  "recvfrom",
	46:  "sendmsg",
	47:  "recvmsg",
	48:  "shutdown",
	49:  "bind",
	50:  "listen",
	51:  "getsockname",
	52:  "getpeername",
	53:  "socketpair",
	54:  "setsockopt",
	55:  "getsockopt",
	56:  "clone",
	57:  "fork",
	58:  "vfork",
	59:  "execve",
	60:  "exit",
	61:  "wait4",
	62:  "kill",
	63:  "uname",
	64:  "semget",
	65:  "semop",
	66:  "semctl",
	67:  "shmdt",
	68:  "msgget",
	69:  "msgsnd",
	70:  "msgrcv",
	71:  "msgctl",
	72:  "fcntl",
	73:  "flock",
	74:  "fsync",
	75:  "fdatasync",
	76:  "truncate",
	77:  "ftruncate",
	78:  "getdents",
	79:  "getcwd",
	80:  "chdir",
	81:  "fchdir",
	82:  "rename",
	83:  "mkdir",
	84:  "rmdir",
	85:  "creat",
	86:  "link",
	87:  "unlink",
	88:  "symlink",
	89:  "readlink",
	90:  "chmod",
	91:  "fchmod",
	92:  "chown",
	93:  "fchown",
	94:  "lchown",
	95:  "umask",
	96:  "gettimeofday",
	97:  "getrlimit",
	98:  "getrusage",
	99:  "sysinfo",
	100: "times",
	101: "ptrace",
	102: "getuid",
	103: "syslog",
	104: "getgid",
	105: "setuid",
	106: "setgid",
	107: "geteuid",
	108: "getegid",
	109: "setpgid",
	110: "getppid",
	111: "getpgrp",
	112: "setsid",
	113: "setreuid",
	114: "setregid",
	115: "getgroups",
	116: "setgroups",
	117: "setresuid",
	118: "getresuid",
	119: "setresgid",
	120: "getresgid",
	121: "getpgid",
	122: "setfsuid",
	123: "setfsgid",
	124: "getsid",
	125: "capget",
	126: "capset",
	127: "rt_sigpending",
	128: "rt_sigtimedwait",
	129: "rt_sigqueueinfo",
	130: "rt_sigsuspend",
	131: "sigaltstack",
	132: "utime",
	133: "mknod",
	134: "uselib",
	135: "personality",
	136: "ustat",
	137: "statfs",
	138: "fstatfs",
	139: "sysfs",
	140: "getpriority",
	141: "setpriority",
	142: "sched_setparam",
	143: "sched_getparam",
	144: "sched_setscheduler",
	145: "sched_getscheduler",
	146: "sched_get_priority_max",
	147: "sched_get_priority_min",
	148: "sched_rr_get_interval",
	149: "mlock",
	150: "munlock",
	151: "mlockall",
	152: "munlockall",
	153: "vhangup",
	154: "modify_ldt",
	155: "pivot_root",
	156: "_sysctl",
	157: "prctl",
	158: "arch_prctl",
	159: "adjtimex",
	160: "setrlimit",
	161: "chroot",
	162: "sync",
	163: "acct",
	164: "settimeofday",
	165: "mount",
	166: "umount2",
	167: "swapon",
	168: "swapoff",
	169: "reboot",
	170: "sethostname",
	171: "setdomainname",
	172: "iopl",
	173: "ioperm",
	174: "create_module",
	175: "init_module",
	176: "delete_module",
	177: "get_kernel_syms",
	178: "query_module",
	179: "quotactl",
	180: "nfsservctl",
	181: "getpmsg",
	182: "putpmsg",
	183: "afs_syscall",
	184: "tuxcall",
	185: "security",
	186: "gettid",
	187: "readahead",
	188: "setxattr",
	189: "lsetxattr",
	190: "fsetxattr",
	191: "getxattr",
	192: "lgetxattr",
	193: "fgetxattr",
	194: "listxattr",
	195: "llistxattr",
	196: "flistxattr",
	197: "removexattr",
	198: "lremovexattr",
	199: "fremovexattr",
	200: "tkill",
	201: "time",
	202: "futex",
	203: "sched_setaffinity",
	204: "sched_getaffinity",
	205: "set_thread_area",
	206: "io_setup",
	207: "io_destroy",
	208: "io_getevents",
	209: "io_submit",
	210: "io_cancel",
	211: "get_thread_area",
	212: "lookup_dcookie",
	213: "epoll_create",
	214: "epoll_ctl_old",
	215: "epoll_wait_old",
	216: "remap_file_pages",
	217: "getdents64",
	218: "set_tid_address",
	219: "restart_syscall",
	220: "semtimedop",
	221: "fadvise64",
	222: "timer_create",
	223: "timer_settime",
	224: "timer_gettime",
	225: "timer_getoverrun",
	226: "timer_delete",
	227: "clock_settime",
	228: "clock_gettime",
	229: "clock_getres",
	230: "clock_nanosleep",
	231: "exit_group",
	232: "epoll_wait",
	233: "epoll_ctl",
	234: "tgkill",
	235: "utimes",
	236: "vserver",
	237: "mbind",
	238: "set_mempolicy",
	239: "get_mempolicy",
	240: "mq_open",
	241: "mq_unlink",
	242: "mq_timedsend",
	243: "mq_timedreceive",
	244: "mq_notify",
	245: "mq_getsetattr",
	246: "kexec_load",
	247: "waitid",
	248: "add_key",
	249: "request_key",
	250: "keyctl",
	251: "ioprio_set",
	252: "ioprio_get",
	253: "inotify_init",
	254: "inotify_add_watch",
	255: "inotify_rm_watch",
	256: "migrate_pages",
	257: "openat",
	258: "mkdirat",
	259: "mknodat",
	260: "fchownat",
	261: "futimesat",
	262: "newfstatat",
	263: "unlinkat",
	264: "renameat",
	265: "linkat",
	266: "symlinkat",
	267: "readlinkat",
	268: "fchmodat",
	269: "faccessat",
	270: "pselect6",
	271: "ppoll",
	272: "unshare",
	273: "set_robust_list",
	274: "get_robust_list",
	275: "splice",
	276: "tee",
	277: "sync_file_range",
	278: "vmsplice",
	279: "move_pages",
	280: "utimensat",
	281: "epoll_pwait",
	282: "signalfd",
	283: "timerfd_create",
	284: "eventfd",
	285: "fallocate",
	286: "timerfd_settime",
	287: "timerfd_gettime",
	288: "accept4",
	289: "signalfd4",
	290: "eventfd2",
	291: "epoll_create1",
	292: "dup3",
	293: "pipe2",
	294: "inotify_init1",
	295: "preadv",
	296: "pwritev",
	297: "rt_tgsigqueueinfo",
	298: "perf_event_open",
	299: "recvmmsg",
	300: "fanotify_init",
	301: "fanotify_mark",
	302: "prlimit64",
	303: "name_to_handle_at",
	304: "open_by_handle_at",
	305: "clock_adjtime",
	306: "syncfs",
	307: "sendmmsg",
	308: "setns",
	309: "getcpu",
	310: "process_vm_readv",
	311: "process_vm_writev",
	312: "kcmp",
	313: "finit_module",
	314: "sched_setattr",
	315: "sched_getattr",
	316: "renameat2",
	317: "seccomp",
	318: "getrandom",
	319: "memfd_create",
	320: "kexec_file_load",
	321: "bpf",
	322: "execveat",
	323: "userfaultfd",
	324: "membarrier",
	325: "mlock2",
	326: "copy_file_range",
	327: "preadv2",
	328: "pwritev2",
	329: "pkey_mprotect",
	330: "pkey_alloc",
	331: "pkey_free",
	332: "statx",
	333: "io_pgetevents",
	334: "rseq",
	335: "uretprobe",
	424: "pidfd_send_signal",
	425: "io_uring_setup",
	426: "io_uring_enter",
	427: "io_uring_register",
	428: "open_tree",
	429: "move_mount",
	430: "fsopen",
	431: "fsconfig",
	432: "fsmount",
	433: "fspick",
	434: "pidfd_open",
	435: "clone3",
	436: "close_range",
	437: "openat2",
	438: "pidfd_getfd",
	439: "faccessat2",
	440: "process_madvise",
	441: "epoll_pwait2",
	442: "mount_setattr",
	443: "quotactl_fd",
	444: "landlock_create_ruleset",
	445: "landlock_add_rule",
	446: "landlock_restrict_self",
	447: "memfd_secret",
	448: "process_mrelease",
	449: "futex_waitv",
	450: "set_mempolicy_home_node",
	451: "cachestat",
	452: "fchmodat2",
	453: "map_shadow_stack",
	454: "futex_wake",
	455: "futex_wait",
	456: "futex_requeue",
	457: "statmount",
	458: "listmount",
	459: "lsm_get_self_attr",
	460: "lsm_set_self_attr",
	461: "lsm_list_modules",
	462: "mseal",
	463: "setxattrat",
	464: "getxattrat",
	465: "listxattrat",
	466: "removexattrat",
	467: "open_tree_attr",
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
