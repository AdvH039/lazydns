CFLAGS = -Wall -Wextra -O2 -g -c
LINT = golangci-lint run
.PHONY: lazydns lazydns-dev format

lazydns-dev:
	cd ./daemon/ebpf && GOPACKAGE="ebpf" bpf2go -target=amd64 bpf ../../ebpf/src/bpf_prog.c -- $(CFLAGS)
	go build -o lazydns .

lazydns: 
	go build -o lazydns .
format:
	go fmt ./...



