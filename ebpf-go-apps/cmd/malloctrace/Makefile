ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    GOARCH := amd64
    LIBC_PATH := /lib/x86_64-linux-gnu/libc.so.6
else ifeq ($(ARCH),aarch64)
    GOARCH := arm64
    LIBC_PATH := /lib/aarch64-linux-gnu/libc.so.6
else
    $(error Unsupported architecture: $(ARCH))
endif

init:
	go clean -cache
	rm -rf bin
	go mod init github.com/edcelvista/ebpf-demo
	go get github.com/cilium/ebpf
	go mod tidy

generate:
	cd ../../bpf/ && make

run: 
	go run .

build:
	rm -rf bin
	mkdir bin
	GOARCH=$(GOARCH) go build -o bin/malloctrace .

clean:
	go clean -cache
	rm -rf bin
