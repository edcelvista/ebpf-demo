package main

import (
	"bytes"
	"encoding/binary"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type Event struct { // This must correspond to your C structure:
	Message [32]byte
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil { // Addressess (MEMLOCK may be too low) | Allow eBPF memory allocation
		log.Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpec("../bpf/helloworld.bpf.o") // Load the eBPF object , clang -target bpf  parses that ELF object.
	if err != nil {
		log.Fatal(err)
	}

	coll, err := ebpf.NewCollection(spec) // Creates athe actual kernel-side eBPF objects
	// coll
	// ├── Programs
	// │   └── hello
	// │
	// └── Maps
	// 	└── events

	if err != nil {
		log.Fatal(err)
	}
	defer coll.Close()

	// Attach the eBPF program to the kprobe. Attach the eBPF program called hello to the kernel function do_sys_openat2
	// SEC("kprobe/do_sys_openat2")
	// int hello(void *ctx)
	kp, err := link.Kprobe("do_sys_openat2", coll.Programs["hello"], nil)
	if err != nil {
		log.Fatal(err)
	}
	defer kp.Close()

	// Open the ring buffer.
	rd, err := ringbuf.NewReader(coll.Maps["events"])
	// struct { // coll
	// __uint(type, BPF_MAP_TYPE_RINGBUF);
	// __uint(max_entries, 1 << 24);
	// } events SEC(".maps");

	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	log.Println("eBPF program loaded")
	log.Println("waiting for events...")

	for { // wait for the events, keeps waiting forever
		record, err := rd.Read()

		if err != nil {
			log.Fatal(err)
		}

		var event Event

		if err := binary.Read(
			bytes.NewReader(record.RawSample),
			binary.NativeEndian,
			&event,
		); err != nil {
			log.Fatal(err)
		}

		message := bytes.TrimRight(event.Message[:], "\x00") // [H][e][l][l][o][,][ ][e][B][P][F][!][\0]... | remove trailing null bytes

		log.Printf("EVENT: %s", message)
	}
}
