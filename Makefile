CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

.PHONY: all format generate build

all: build

build:
	go mod tidy
	go build -o ./bin/nperf

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./ebpf/c/vmlinux.h
	go generate -x ./...

format:
	find . -type f \( -name '*.[ch]' -and -not -name 'vmlinux.h' \) -exec clang-format -i {} \;
