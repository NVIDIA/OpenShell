all: test

check:
	@cargo check --lib --all-features

build:
	@cargo build --all-features

doc:
	@cargo doc --all-features

test:
	@echo "CARGO TESTS"
	@cargo test
	@cargo test --all-features
	@cargo test --no-default-features

check-minver:
	@echo "MINVER CHECK"
	@cargo minimal-versions check --lib
	@cargo minimal-versions check --lib --all-features
	@cargo minimal-versions check --lib --no-default-features

format:
	@rustup component add rustfmt 2> /dev/null
	@cargo fmt --all

format-check:
	@rustup component add rustfmt 2> /dev/null
	@cargo fmt --all -- --check

lint:
	@rustup component add clippy 2> /dev/null
	@cargo clippy --examples --tests --all-features -- --deny warnings

.PHONY: all doc build check test format format-check lint check-minver msrv-lock
