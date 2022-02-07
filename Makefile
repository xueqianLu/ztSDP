export GO111MODULE := on

all: generate-version-and-build

MAKEFLAGS += --no-print-directory

generate-version-and-build:
	@export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" && \
	tag="$$(git describe --dirty 2>/dev/null)" && \
	ver="$$(printf 'package device\nconst ZtSDPGoVersion = "%s"\n' "$${tag#v}")" && \
	[ "$$(cat device/version.go 2>/dev/null)" != "$$ver" ] && \
	echo "$$ver" > device/version.go && \
	git update-index --assume-unchanged device/version.go || true
	@$(MAKE) ztSDP

ztSDP: $(wildcard *.go) $(wildcard */*.go)
	go build -v -o "$@"

test:
	go test ./...

clean:
	rm -f ztSDP

.PHONY: all clean test generate-version-and-build
