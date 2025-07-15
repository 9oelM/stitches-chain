.PHONY: format fix-format lint fix-lint check all

format:
	cargo fmt --all -- --check

fix-format:
	cargo fmt --all

lint:
	cargo clippy --all-targets --all-features -- -D warnings

fix-lint:
	cargo clippy --all-targets --all-features --fix --allow-dirty -- -D warnings

check: format lint

all: fix-format fix-lint
