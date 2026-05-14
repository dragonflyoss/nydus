CARGO ?= cargo
GO    ?= go

.PHONY: build release test test-integration test-perf clean

build:
	$(CARGO) build

release:
	$(CARGO) build --release

test:
	$(CARGO) test --workspace

# Run integration tests (requires root, builds release first).
# Includes verification tests (~1s) and xfstests regression (~90s).
# First run will install xfstests dependencies via tests/scripts/setup_xfstests.sh.
test-integration: release
	cd tests/integration && \
		sudo env "PATH=$(PATH)" "HOME=$(HOME)" \
		"GOMODCACHE=$$($(GO) env GOMODCACHE)" \
		LEPTONFS_RUN_XFSTESTS=1 \
		$(GO) test -v -timeout 600s ./...

# Run performance benchmark (requires root, fio, ~2min).
# Compares Rust `lepton mount` vs C erofsfuse (auto-detected or EROFS_C_FUSE=path).
test-perf: release
	cd tests/integration && \
		sudo env "PATH=$(PATH)" "HOME=$(HOME)" \
		"GOMODCACHE=$$($(GO) env GOMODCACHE)" \
		EROFS_RUN_PERF=1 \
		$(GO) test -v -run TestPerf -timeout 300s ./...

clean:
	$(CARGO) clean
