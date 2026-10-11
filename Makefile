PHONY: build install

build:
	cargo build --release

install: build
	cp target/release/rip-xz rz
	cargo clean