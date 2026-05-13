#!/bin/bash
# profile-erofs-fuse.sh — Automated flamegraph profiling for `lepton fuse mount`
#
# Usage:   sudo ./scripts/profile-erofs-fuse.sh
# Output:  /tmp/erofs-profile/flame.svg
#
# Prerequisites:
#   - cargo build --release (with [profile.release] debug = true)
#   - perf, fio, inferno-collapse-perf, inferno-flamegraph
#   - lepton built

set -euo pipefail

PROJ_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LEPTON="${PROJ_DIR}/target/release/lepton"

# Ensure cargo-installed binaries are in PATH (sudo often strips ~/.cargo/bin)
for d in /home/*/.cargo/bin "${HOME}/.cargo/bin"; do
    [[ -d "$d" ]] && export PATH="$d:$PATH"
done
WORK_DIR="/tmp/erofs-profile"
CORPUS_DIR="${WORK_DIR}/corpus"
IMG="${WORK_DIR}/test.erofs"
BLOB="${WORK_DIR}/test.blob"
MNT="${WORK_DIR}/mnt"
PERF_DATA="${WORK_DIR}/perf.data"
FLAME_SVG="${WORK_DIR}/flame.svg"
PERF_DURATION="${PERF_DURATION:-15}"
FUSE_THREADS="${FUSE_THREADS:-1}"

# ── helpers ──────────────────────────────────────────────────────────
die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

cleanup() {
    info "Cleaning up..."
    fusermount -u "${MNT}" 2>/dev/null || true
    # Kill lepton fuse mount if still running
    if [[ -n "${FUSE_PID:-}" ]] && kill -0 "${FUSE_PID}" 2>/dev/null; then
        kill "${FUSE_PID}" 2>/dev/null || true
        wait "${FUSE_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ── checks ───────────────────────────────────────────────────────────
[[ $(id -u) -eq 0 ]] || die "must run as root (sudo)"
command -v perf              >/dev/null || die "perf not found"
command -v fio               >/dev/null || die "fio not found"
command -v inferno-collapse-perf >/dev/null || die "inferno-collapse-perf not found (cargo install inferno)"
command -v inferno-flamegraph    >/dev/null || die "inferno-flamegraph not found"
[[ -x "${LEPTON}" ]]    || die "${LEPTON} not found — run: cargo build --release"

# ── prepare workspace ───────────────────────────────────────────────
info "Preparing workspace in ${WORK_DIR}"
rm -rf "${WORK_DIR}"
mkdir -p "${CORPUS_DIR}/large" "${MNT}"

# Generate corpus: 4 × 32 MB files
for i in 0 1 2 3; do
    dd if=/dev/urandom of="${CORPUS_DIR}/large/file_${i}.bin" bs=1M count=32 status=none
done
info "Corpus ready (~128 MB)"

# ── build EROFS image ───────────────────────────────────────────────
info "Building EROFS image (chunksize=1M)..."
"${LEPTON}" mkfs "${IMG}" --blobdev "${BLOB}" --chunksize 1048576 "${CORPUS_DIR}"

# ── mount lepton fuse mount ─────────────────────────────────────────
info "Mounting lepton fuse mount (threads=${FUSE_THREADS})..."
"${LEPTON}" fuse mount "${IMG}" "${MNT}" --blobdev "${BLOB}" --threads "${FUSE_THREADS}" &
FUSE_PID=$!

# Wait for mount
for i in $(seq 1 40); do
    if mountpoint -q "${MNT}" 2>/dev/null; then
        break
    fi
    sleep 0.25
done
mountpoint -q "${MNT}" || die "lepton fuse mount failed to mount within 10s"
info "Mounted (PID=${FUSE_PID})"

# ── warm up (prime page cache, then drop) ────────────────────────────
info "Warming up..."
cat "${MNT}/large/file_0.bin" > /dev/null 2>&1 || true
echo 3 > /proc/sys/vm/drop_caches
sleep 1

# ── perf record ──────────────────────────────────────────────────────
info "Starting perf record (${PERF_DURATION}s, sampling at 4999 Hz)..."
perf record -g -F 4999 -p "${FUSE_PID}" -o "${PERF_DATA}" -- sleep "${PERF_DURATION}" &
PERF_PID=$!

# Run fio sequential read benchmark
info "Running fio sequential read (128K, ${PERF_DURATION}s)..."
fio --name=seqread \
    --filename="${MNT}/large/file_0.bin" \
    --rw=read --bs=128k --direct=0 \
    --numjobs=1 --runtime="${PERF_DURATION}" --time_based --readonly \
    --output-format=normal 2>&1 | grep -E 'READ:|BW|iops'

# Wait for perf to finish
wait "${PERF_PID}" || true
info "perf record done: ${PERF_DATA}"

# ── generate flamegraph ──────────────────────────────────────────────
info "Generating flamegraph..."
perf script -i "${PERF_DATA}" | \
    inferno-collapse-perf --all | \
    inferno-flamegraph --title "lepton fuse mount sequential read 128K (threads=${FUSE_THREADS})" \
    > "${FLAME_SVG}"

info "Flamegraph saved: ${FLAME_SVG}"
ls -lh "${FLAME_SVG}"

# ── quick text analysis ──────────────────────────────────────────────
info "Top 20 hottest functions:"
perf script -i "${PERF_DATA}" | \
    inferno-collapse-perf --all | \
    awk -F';' '{print $NF}' | \
    sort | uniq -c | sort -rn | head -20

# ── also run perf report summary ────────────────────────────────────
info "perf report summary (top 15):"
perf report -i "${PERF_DATA}" --stdio --no-children --percent-limit 1 2>/dev/null | head -30

echo ""
info "Done! Open ${FLAME_SVG} in a browser for interactive analysis."
info "To re-run with different settings:"
info "  PERF_DURATION=30 FUSE_THREADS=4 sudo ./scripts/profile-erofs-fuse.sh"
