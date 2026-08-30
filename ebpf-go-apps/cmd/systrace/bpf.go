package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux systrace ../../bpf/systrace.bpf.c
