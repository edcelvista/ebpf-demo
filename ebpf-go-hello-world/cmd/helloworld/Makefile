init:
	go clean -cache
	rm -rf bin
	go mod init github.com/edcelvista/ebpf-demo
	go get github.com/cilium/ebpf
	go mod tidy

run: 
	go run .

build:
	rm -rf bin
	mkdir bin
	go build -o bin/helloworld .

clean:
	go clean -cache
	rm -rf bin
