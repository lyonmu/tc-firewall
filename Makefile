VERSION =  $(shell git describe --tags --exact-match 2>/dev/null || git branch  --show-current )
REVISION = $(shell git rev-parse HEAD)
BRANCH = $(shell git branch  --show-current)
COMPILE_TIME= $(shell date +"%Y-%m-%d %H:%M:%S")
USER = $(shell  git log -1 --pretty=format:"%an")
PROJECT_NAME = $(notdir $(CURDIR))
FLAGS = -ldflags "-s -w \
	-X 'github.com/prometheus/common/version.Version=${VERSION}' \
	-X 'github.com/prometheus/common/version.Revision=${REVISION}' \
	-X 'github.com/prometheus/common/version.Branch=${BRANCH}' \
	-X 'github.com/prometheus/common/version.BuildUser=${USER}' \
	-X 'github.com/prometheus/common/version.BuildDate=${COMPILE_TIME}'"

TAGS = -tags="sonic avx netgo osusergo"

.PHONY: build build-amd64 build-386 build-arm build-arm64 build-all clean ebpf help

default: build

ebpf:
	cd ebpf && go generate -tags linux ./...

build: build-amd64

build-amd64: ebpf
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ${FLAGS} ${TAGS} -o bin/${PROJECT_NAME} main.go

build-386: ebpf
	CGO_ENABLED=0 GOOS=linux GOARCH=386 go build ${FLAGS} ${TAGS} -o bin/${PROJECT_NAME}-386 main.go

build-arm: ebpf
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build ${FLAGS} ${TAGS} -o bin/${PROJECT_NAME}-arm main.go

build-arm64: ebpf
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ${FLAGS} ${TAGS} -o bin/${PROJECT_NAME}-arm64 main.go

build-all: build-amd64 build-386 build-arm build-arm64

clean:
	rm -rf bin/
	rm -f ebpf/port_protection/portprotection_*.go ebpf/port_protection/portprotection_*.o

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  build       Build for current platform (default: amd64)"
	@echo "  build-amd64 Build for x86_64 (64-bit)"
	@echo "  build-386   Build for x86 (32-bit)"
	@echo "  build-arm   Build for ARM (32-bit)"
	@echo "  build-arm64 Build for ARM64 (64-bit)"
	@echo "  build-all   Build for all platforms"
	@echo "  ebpf        Generate eBPF Go bindings"
	@echo "  clean       Clean build artifacts"
	@echo "  help        Show this help message"
