package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

var arch = map[string]string{
	"x86_64":        "/lib/x86_64-linux-gnu/libc.so.6",
	"amd64":         "/lib/x86_64-linux-gnu/libc.so.6",
	"arm64":         "/lib/aarch64-linux-gnu/libc.so.6",
	"aarch64":       "/lib/aarch64-linux-gnu/libc.so.6",
	"arm":           "/lib/arm-linux-gnueabihf/libc.so.6",
	"armhf":         "/lib/arm-linux-gnueabihf/libc.so.6",
	"i386":          "/lib/i386-linux-gnu/libc.so.6",
	"386":           "/lib/i386-linux-gnu/libc.so.6",
	"risc-v 64":     "/lib/riscv64-linux-gnu/libc.so.6",
	"powerpc 64 le": "/lib/powerpc64le-linux-gnu/libc.so.6",
	"s390x":         "/lib/s390x-linux-gnu/libc.so.6",
}

type Event struct { // This must correspond to your C structure: tcp_event
	TimestampNs uint64
	Size        uint64
	StactId     uint64
	PID         uint32
	Tgid        uint32
	Uid         uint32
	Comm        string

	Cwd string // user-space
	Cmd string // user-space
}

func main() {
	spec, err := ebpf.LoadCollectionSpec("../../bpf/bin/malloctrace.bpf.o")
	if err != nil {
		log.Fatal(err)
	}

	for name, progSpec := range spec.Programs {
		fmt.Printf("eBPF Program=%s Section=%s\n", name, progSpec.SectionName)
	}

	/*
		coll
		├── Programs
		│   └── trace_malloc
		│
		└── Maps
			└── events
	*/
	coll, err := ebpf.NewCollection(spec) // Creates athe actual kernel-side eBPF objects
	if err != nil {
		log.Fatal(err)
	}
	defer coll.Close()

	libcPathfile, ok := arch[strings.ToLower(runtime.GOARCH)]
	if !ok {
		log.Fatalf("unknown(%d)", strings.ToLower(runtime.GOARCH))
	}

	/*
		Attach the eBPF program uprobe which attaches to a user-spaces intstruction unlike kprobe to a kernel function | Find the malloc symbol inside this ELF executable/shared library.
		SEC("uprobe/malloc")
		int trace_malloc(void *ctx)
	*/
	fmt.Printf("Arch: %s | libcPath: %s\n", strings.ToLower(runtime.GOARCH), libcPathfile)
	exe, err := link.OpenExecutable(libcPathfile)
	if err != nil {
		log.Fatal(err)
	}

	/* Attach:
	SEC("uprobe/malloc")
	*/

	up, err := exe.Uprobe("malloc", coll.Programs["trace_malloc"], nil)
	if err != nil {
		log.Fatal(err)
	}
	defer up.Close()

	reader, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		log.Fatal(err)
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

		// [DEBUG] check for size mismatch
		// fmt.Printf("RawSample size = %d\n", len(record.RawSample)) // BPF size
		// fmt.Printf("Expected size = %d\n", binary.Size(Event{}))   // go trying to decode 42 bytes
		// if len(record.RawSample) < 40 {
		// 	log.Printf("short event: got %d bytes", len(record.RawSample))
		// 	continue
		// }

		var event Event
		// Decode directly from RawSample removes bytes.NewReader() and binary.Read() from the equation.
		event.TimestampNs = binary.LittleEndian.Uint64(record.RawSample[0:8])
		event.Size = binary.LittleEndian.Uint64(record.RawSample[8:16])
		event.StactId = binary.LittleEndian.Uint64(record.RawSample[16:24])
		event.PID = binary.LittleEndian.Uint32(record.RawSample[24:28])
		event.Tgid = binary.LittleEndian.Uint32(record.RawSample[28:32])
		event.Uid = binary.LittleEndian.Uint32(record.RawSample[32:36])
		event.Comm = string(record.RawSample[36:52])

		if event.Size < 10485760 { // skip less than 10mb
			continue
		}

		cwd, cmd := getPIDCWD_CMD(event.PID)
		event.Cwd = cwd
		event.Cmd = cmd

		fmt.Printf(
			"%d PID=%d COMM=%s CWD=%s CMD=%s SID=%d TGID=%d UID=%d SIZE=%s\n",
			event.TimestampNs,
			event.PID,
			event.Comm,
			event.Cwd,
			event.Cmd,
			event.StactId,
			event.Tgid,
			event.Uid,
			fmt.Sprintf("malloc: %d bytes: (%.2f MB)", event.Size, float64(event.Size)/(1024*1024)),
		)
	}
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
