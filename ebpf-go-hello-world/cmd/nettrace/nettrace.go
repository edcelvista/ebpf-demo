package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Event struct { // This must correspond to your C structure: tcp_event
	TimestampNs uint64
	LatencyNs   uint64

	PID  uint32
	TGID uint32

	Saddr uint32
	Daddr uint32

	Sport uint16
	Dport uint16

	OldState uint8
	NewState uint8
	Family   uint16

	Comm string
	Cwd  string // user-space
	Cmd  string // user-space
}

func main() {
	// Load generated BPF objects. by go generate
	objs := nettraceObjects{}
	if err := loadNettraceObjects(&objs, nil); err != nil {
		log.Fatalf("loading BPF objects: %v", err)
	}
	defer objs.Close()

	/* Attach:
	SEC("tracepoint/sock/inet_sock_set_state")
	*/
	tp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TraceTcpState, nil)
	if err != nil {
		log.Fatalf("attaching tracepoint: %v", err)
	}
	defer tp.Close()

	log.Println("eBPF NET TRACER Running...")

	// Read the BPF ring buffer.
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("creating ringbuf reader: %v", err)
	}
	defer reader.Close()

	// Handle Ctrl-C.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		<-sig // Wait until something is received from the sig channel.

		/*
		 * Closing the ring buffer wakes Read().
		 */
		_ = reader.Close()
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
		event.LatencyNs = binary.LittleEndian.Uint64(record.RawSample[8:16])
		event.PID = binary.LittleEndian.Uint32(record.RawSample[16:20])
		event.TGID = binary.LittleEndian.Uint32(record.RawSample[20:24])
		event.Saddr = binary.LittleEndian.Uint32(record.RawSample[24:28])
		event.Daddr = binary.LittleEndian.Uint32(record.RawSample[28:32])
		event.Sport = binary.LittleEndian.Uint16(record.RawSample[32:34])
		event.Dport = binary.LittleEndian.Uint16(record.RawSample[34:36])
		event.OldState = record.RawSample[36]
		event.NewState = record.RawSample[37]
		event.Family = binary.LittleEndian.Uint16(record.RawSample[38:40])
		event.Comm = string(record.RawSample[40:56])

		cwd, cmd := getPIDCWD_CMD(event.PID)
		event.Cwd = cwd
		event.Cmd = cmd

		/*
		 * bytes.NewReader does NOT copy RawSample.
		 */
		// reader := bytes.NewReader(record.RawSample) // DO NOT COPY per event as it will compound and cause memory leak
		// err = binary.Read(reader, binary.LittleEndian, &event)
		// if err := binary.Read(
		// 	reader,
		// 	binary.LittleEndian,
		// 	&event,
		// ); err != nil {
		// 	log.Printf("decoding event: %v", err)
		// 	continue
		// }

		fmt.Printf(
			"%d PID=%d COMM=%s CWD=%s CMD=%s CONN=%s:%d->%s:%d[%s]->[%s] LATENCY=%fs\n",
			event.TimestampNs,
			event.PID,
			event.Comm,
			event.Cwd,
			event.Cmd,
			ipv4(event.Saddr),
			event.Sport,
			ipv4(event.Daddr),
			ntohs(event.Dport),
			tcpState(event.OldState),
			tcpState(event.NewState),
			float64(event.LatencyNs)/1e9,
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

func ntohs(v uint16) uint16 {
	/*
		This swaps the two bytes of a 16-bit value.
		It's commonly used to convert between network byte order (big-endian) and host byte order (little-endian) for TCP/UDP ports.
	*/
	return (v << 8) | (v >> 8)
}

func ipv4(addr uint32) net.IP {
	/*
			in C
			info->saddr = BPF_CORE_READ(
				sk,
				__sk_common.skc_rcv_saddr
			);

			looks unordered

			uint32:
			0x0A 01 A8 C0
			  ↑   ↑  ↑  ↑
			10  1 168 192

			192.168.1.10
			192     168     1       10
			↓       ↓      ↓        ↓
			1 byte  1 byte  1 byte  1 byte

			addr = 0x0A01A8C0
					24       16        8        0
					↓        ↓        ↓        ↓
				 ┌──────┬────────┬────────┬────────┐
		    addr │  0A  │   01   │   A8   │   C0   │
				 └──────┴────────┴────────┴────────┘
					│        │        │        │
					>>24     >>16      >>8       0
					│        │        │        │
					▼        ▼        ▼        ▼
					10        1       168      192

			net.IPv4(192, 168, 1, 10)

			addr >> 8 moves everything 8 bits to the right:
			0x0A01A8C0
			↓↓↓
			0x000A01A8
	*/
	return net.IPv4( // becomes net.IPv4(192, 168, 1, 10)
		byte(addr),     // 0xC0 = 192
		byte(addr>>8),  // 0xA8 = 168
		byte(addr>>16), // 0x01 = 1
		byte(addr>>24), // 0x0A = 10
	)
}

func tcpState(state uint8) string {
	switch state {
	case 1:
		return "ESTABLISHED"
	case 2:
		return "SYN_SENT"
	case 3:
		return "SYN_RECV"
	case 4:
		return "FIN_WAIT1"
	case 5:
		return "FIN_WAIT2"
	case 6:
		return "TIME_WAIT"
	case 7:
		return "CLOSE"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "LAST_ACK"
	case 10:
		return "LISTEN"
	case 11:
		return "CLOSING"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", state)
	}
}
