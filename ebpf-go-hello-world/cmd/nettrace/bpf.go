package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux nettrace ../../bpf/nettrace.bpf.c
