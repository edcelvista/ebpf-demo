CLANG = clang
LLC = llc

BPF_CFLAGS = -I /usr/include/aarch64-linux-gnu -O2 -g -target bpf -D__TARGET_ARCH_arm64

TARGET = helloworld
BPF_OBJ = $(TARGET).bpf.o

all: $(BPF_OBJ)

$(BPF_OBJ): $(TARGET).bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f $(BPF_OBJ)
