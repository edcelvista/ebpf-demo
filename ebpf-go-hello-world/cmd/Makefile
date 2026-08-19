init:
	go clean -cache
	rm go.*
	go mod init github.com/edcelvista/ebpf-demo
	go get github.com/cilium/ebpf
	go mod tidy

build:
	go build -o helloworld .

clean:
	go clean -cache
	rm go.*
