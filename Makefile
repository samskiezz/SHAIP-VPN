.PHONY: all client server control web test test-rust test-go build clean fmt selftest

all: build

build: client server control web

client:
	cargo build --release -p pqanon-client

server:
	cargo build --release -p pqanon-server

control:
	cd control-plane && go build -o bin/control-plane .

web:
	cd web-ui && npm ci && npm run build

test: test-rust test-go

test-rust:
	cargo test

test-go:
	cd control-plane && go vet ./... && go test ./...

selftest: client
	./target/release/pqanon selftest

fmt:
	cargo fmt
	cd control-plane && go fmt ./...

clean:
	cargo clean
	rm -rf control-plane/bin
	rm -rf web-ui/.next web-ui/node_modules
