.PHONY: all client server control web test test-rust test-go test-all build clean fmt selftest

all: build

build: client server control web

client:
	cargo build --release -p shaip-client

server:
	cargo build --release -p shaip-server

control:
	cd control-plane && go build -o bin/control-plane .

web:
	cd web-ui && npm ci && npm run build

test: test-rust test-go

test-rust:
	cargo test

test-go:
	cd control-plane && go vet ./... && go test ./...

# Full battery: build, lint, unit, integration, fuzz, stress, smoke, brute,
# race, live TUN, and live control-plane sign-up end-to-end.
test-all:
	./scripts/test-all.sh

selftest: client
	./target/release/shaip selftest

fmt:
	cargo fmt
	cd control-plane && go fmt ./...

clean:
	cargo clean
	rm -rf control-plane/bin
	rm -rf web-ui/.next web-ui/node_modules
