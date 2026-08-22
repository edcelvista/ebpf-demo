CLANG = clang
LLC = llc

BPF_CFLAGS = -I /usr/include/aarch64-linux-gnu -O2 -g -target bpf -D__TARGET_ARCH_arm64

TARGET = malloctrace
BPF_OBJ = $(TARGET).bpf.o

all: $(BPF_OBJ)

$(BPF_OBJ): $(TARGET).bpf.c
	rm -rf bin
	mkdir bin
	$(CLANG) $(BPF_CFLAGS) -c $< -o bin/$@

clean:
	rm -f bin/$(BPF_OBJ)
