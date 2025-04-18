CFLAGS = -Wall -Wextra -O2 -g -c
LINT = golangci-lint run
.PHONY: lazydns lazydns-dev format clang-format

lazydns-dev:
	cd ./pkg/ebpf && GOPACKAGE="ebpf" bpf2go -target=amd64 bpf ../../ebpf/src/bpf_prog.c -- $(CFLAGS)
	go build -o lazydns .

lazydns: 
	go build -o lazydns .
format:
	go fmt ./...
clang-format:
	find . -name "*.c" -o -name "*.h" | xargs clang-format -i



