.PHONY: format

format:
	clang-format -i --style="{BasedOnStyle: Google, IndentWidth: 4}" ebpf/*.c ebpf/include/bpf/*.h

.PHONY: build

build:
	CGO_ENABLED=0 go build -o xdp main.go

.PHONY: generate

generate:
	cd ebpf
	go generate ./...