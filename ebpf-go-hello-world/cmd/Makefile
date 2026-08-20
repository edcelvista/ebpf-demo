init:
	go clean -cache
	rm -rf bin
	go mod init github.com/edcelvista/ebpf-demo
	go get github.com/cilium/ebpf
	go mod tidy

generate: # bpf2go generate go bindings from c program | use this to avoid compiling ebpf C code separately
	go generate

build:
	rm -rf bin
	mkdir bin
	go build -o bin/nettrace .

clean:
	go clean -cache
	rm -rf bin
