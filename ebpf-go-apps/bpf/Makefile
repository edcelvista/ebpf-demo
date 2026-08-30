TARGET=malloctrace

CLANG = clang
LLC = llc
BPF_OBJ = $(TARGET).bpf.o

ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
	BPF_FLAG_ARCH := -D__TARGET_ARCH_x86
	LIBC_PATH := /usr/include/x86_64-linux-gnu
else ifeq ($(ARCH),aarch64)
	BPF_FLAG_ARCH := -D__TARGET_ARCH_arm64
	LIBC_PATH := /usr/include/aarch64-linux-gnu
else
	$(error Unsupported architecture: $(ARCH))
endif

BPF_CFLAGS = -I $(LIBC_PATH) -O2 -g -target bpf $(BPF_FLAG_ARCH)

all: $(BPF_OBJ)

$(BPF_OBJ): $(TARGET).bpf.c
	rm -rf bin
	mkdir bin
	$(CLANG) $(BPF_CFLAGS) -c $< -o bin/$@

clean:
	rm -f bin/$(BPF_OBJ)
