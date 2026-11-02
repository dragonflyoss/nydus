#!/usr/bin/env bash
# Runtime collection is enabled by Makefile's explicit CI_COVERAGE=1.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
coverage=${COVERAGE_DIR:-"$root/coverage"}
tools=${COVERAGE_TOOLS_DIR:-"$root/coverage-tools"}
target=${CARGO_TARGET_DIR:-target}
nydus=${NYDUS_BIN:-"$target/ci/nydus"}
nydusify=${NYDUSIFY_BIN:-nydusify/nydusify}
writer=${NYDUS_WRITER_BIN:-"$target/ci/examples/writer-fixture"}

case "${1:-}" in
    bundle)
        # These tools must match the compiler, not Ubuntu's LLVM packages.
        rustc --version | grep -q '^rustc 1\.88\.0 '
        sysroot=$(rustc --print sysroot)
        host=$(rustc -vV | sed -n 's/^host: //p')
        mkdir -p "$tools/bin" "$tools/lib"
        cp "$sysroot/lib/rustlib/$host/bin/llvm-cov" \
            "$sysroot/lib/rustlib/$host/bin/llvm-profdata" "$tools/bin/"
        cp -L "$sysroot"/lib/libLLVM.so* "$tools/lib/"
        rustc -vV > "$tools/rustc-version.txt"
        # Stripping the inherited release profile would lose report symbols.
        readelf -S "$nydus" | grep __llvm_covmap > /dev/null
        readelf -S "$nydus" | grep '\.symtab' > /dev/null
        sha256sum "$nydus" "$nydusify" > "$tools/binaries.sha256"
        if [ -f "$writer" ]; then
            sha256sum "$writer" >> "$tools/binaries.sha256"
        fi
        ;;
    export)
        mkdir -p "$coverage/raw/rust" "$coverage/raw/go"
        outcome=${COVERAGE_TEST_OUTCOME:-unknown}
        {
            echo "test_outcome=$outcome"
            echo "rust_scope=product-e2e"
            echo "go_scope=product-e2e"
            echo "profile_pool=8-per-instrumented-module"
            echo "completeness=partial: SIGKILL, abort and forced timeouts cannot flush counters"
            echo "missing_profile_is_not_zero_coverage=true"
        } > "$coverage/status.txt"
        trap 'echo "collection=export-failed" >> "$coverage/status.txt"' ERR
        shopt -s nullglob
        rust=("$coverage"/raw/rust/*.profraw)
        go=("$coverage"/raw/go/covcounters.*)
        echo "rust_raw_files=${#rust[@]}" >> "$coverage/status.txt"
        echo "go_raw_files=${#go[@]}" >> "$coverage/status.txt"
        if [ "$outcome" = skipped ] || [ "$outcome" = cancelled ]; then
            echo "collection=not-run-or-cancelled" >> "$coverage/status.txt"
            exit 0
        fi
        if [ "${#rust[@]}" -gt 0 ] || [ "${#go[@]}" -gt 0 ]; then
            sha256sum --check "$tools/binaries.sha256"
        fi
        status=0
        if [ "${#rust[@]}" -eq 0 ]; then
            echo "rust_report=missing" >> "$coverage/status.txt"
            echo "error: no Rust profiles; test outcome: $outcome" >&2
            status=1
        else
            chmod +x "$tools/bin/llvm-cov" "$tools/bin/llvm-profdata"
            export LD_LIBRARY_PATH="$tools/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
            "$tools/bin/llvm-profdata" merge -sparse "${rust[@]}" -o "$coverage/rust-e2e.profdata"
            "$tools/bin/llvm-cov" export "$nydus" \
                -instr-profile="$coverage/rust-e2e.profdata" -format=lcov \
                -ignore-filename-regex='(/\.cargo/|/\.rustup/|/rustc/|/tests/|/examples/|/build/[^/]+/out/)' \
                > "$coverage/rust-e2e.lcov.partial"
            test -s "$coverage/rust-e2e.lcov.partial"
            mv "$coverage/rust-e2e.lcov.partial" "$coverage/rust-e2e.lcov"
            echo "rust_report=collected" >> "$coverage/status.txt"
        fi
        if [ "${#go[@]}" -gt 0 ]; then
            for counter in "${go[@]}"; do
                hash=${counter##*/covcounters.}
                test -f "$coverage/raw/go/covmeta.${hash%%.*}" || {
                    echo "go_report=missing-metadata" >> "$coverage/status.txt"
                    echo "error: Go counter has no matching metadata: $counter" >&2
                    exit 1
                }
            done
            "${GO_BIN:-go}" tool covdata textfmt -i="$coverage/raw/go" -o="$coverage/go-e2e.out.partial"
            test "$(wc -l < "$coverage/go-e2e.out.partial")" -gt 1
            mv "$coverage/go-e2e.out.partial" "$coverage/go-e2e.out"
            echo "go_report=collected" >> "$coverage/status.txt"
        else
            echo "go_report=no-profile: this shard may not invoke nydusify; no zero report fabricated" >> "$coverage/status.txt"
            if [ "${COVERAGE_REQUIRE_GO:-0}" = 1 ]; then
                echo "error: expected nydusify subprocess profiles" >&2
                status=1
            fi
        fi
        exit "$status"
        ;;
    *)
        echo "usage: $0 {bundle|export}" >&2
        exit 2
        ;;
esac
