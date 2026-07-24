# QuantaWatch developer tasks. After cloning, run `make setup` once.
#
# On Windows without `make`, run the underlying scripts directly, e.g.
#   bash scripts/setup.sh
.PHONY: help setup sync test build fmt clippy

help: ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-10s %s\n", $$1, $$2}'

setup: ## one-time: enable repo-tracked git hooks for this clone
	@bash scripts/setup.sh

sync: ## regenerate docs/dev-notes/ from the private working notes
	@bash scripts/sync-dev-notes.sh

test: ## run the full workspace test suite
	cargo test --workspace

build: ## build the whole workspace
	cargo build --workspace

fmt: ## format all Rust code
	cargo fmt --all

clippy: ## lint all crates
	cargo clippy --workspace --all-targets
