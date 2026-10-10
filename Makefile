SHELL := bash

# Two kinds of targets:
# - hermetic ones (check, package) go through nix-build (default.nix), in the Nix sandbox;
# - the development loop (test, lint, …) runs inside the pinned nix shell (shell.nix). Already inside
#   `nix-shell`? Then the commands run directly.
ifdef IN_NIX_SHELL
RUN := bash -c
else
RUN := nix-shell --pure shell.nix --run
endif
NIX_BUILD := nix-build --max-jobs auto

.PHONY: all check package test test-backend test-sdk lint fmt build clean

# Everything, hermetic: both packages, lint, the Rust suite, the SDK's unit tests and the VM test, in the Nix
# sandbox. This is what CI runs.
all: check

check:
	$(NIX_BUILD) --no-out-link

# Just the packages (building the backend still runs the Rust suite). result/ and result-2/ link to them.
package:
	$(NIX_BUILD) -A backend -A sdk

# ---------------------------------------------------------------- development loop (incremental, dev shell)

test: test-backend test-sdk

test-backend:
	$(RUN) 'cd backend && cargo test'

test-sdk:
	$(RUN) 'node --test "sdk/test/**/*.test.js"'

lint:
	$(RUN) 'cd backend && cargo fmt --check && cargo clippy --all-targets -- -D warnings'

fmt:
	$(RUN) 'cd backend && cargo fmt'

# backend/target/debug/backend, e.g. for an app's `make run BACKEND=…` while working on both.
build:
	$(RUN) 'cd backend && cargo build'

clean:
	$(RUN) 'cd backend && cargo clean'
