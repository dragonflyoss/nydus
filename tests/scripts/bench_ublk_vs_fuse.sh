#!/usr/bin/env bash
# Compare the ublk block device path against the FUSE path on the same image.
#
# Both mounts serve the same bootstrap and blob directory, so the only variable
# is how the kernel reaches the data: EROFS over /dev/ublkbN versus the nydus
# FUSE server. Results are appended to a CSV.
#
# Usage:
#   sudo ./tests/scripts/bench_ublk_vs_fuse.sh --bootstrap <path> --config <yaml>
#
# Requires root, Linux 6.0+ with ublk_drv, and fio.

set -euo pipefail

NYDUS_BIN=${NYDUS_BIN:-./target/release/nydus}
BOOTSTRAP=""
CONFIG=""
WORKDIR=${WORKDIR:-$(mktemp -d)}
OUTPUT=${OUTPUT:-"${WORKDIR}/bench.csv"}
RUNS=${RUNS:-3}
FIO_RUNTIME=${FIO_RUNTIME:-15}
# Working set per fio job. Keep it well under the host's RAM so the benchmark
# measures the two serving paths rather than the backing disk.
FIO_SIZE=${FIO_SIZE:-128M}
JOBS=${JOBS:-4}

usage() {
    sed -n '2,12p' "$0"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bootstrap) BOOTSTRAP=$2; shift 2 ;;
        --config) CONFIG=$2; shift 2 ;;
        --nydus) NYDUS_BIN=$2; shift 2 ;;
        --output) OUTPUT=$2; shift 2 ;;
        --runs) RUNS=$2; shift 2 ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

[[ -n "$BOOTSTRAP" && -n "$CONFIG" ]] || usage
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
command -v fio >/dev/null || { echo "fio is required" >&2; exit 1; }
modprobe ublk_drv

MNT="${WORKDIR}/mnt"
DEV_PATH=""
DAEMON_PID=""
MODE=""
mkdir -p "$MNT"

cleanup() {
    if mountpoint -q "$MNT"; then
        if [[ "$MODE" == "fuse" ]]; then
            fusermount -u "$MNT" 2>/dev/null || umount "$MNT" 2>/dev/null || true
        else
            umount "$MNT" 2>/dev/null || true
        fi
    fi
    # Always unmount before stopping the daemon: it serves I/O for its own
    # device, so an unmount racing its exit would hang.
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill -TERM "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    DAEMON_PID=""
    MODE=""
}
trap cleanup EXIT

mount_ublk() {
    local out="${WORKDIR}/ublk.out"
    : > "$out"
    "$NYDUS_BIN" ublk --bootstrap "$BOOTSTRAP" --config "$CONFIG" >"$out" 2>"${WORKDIR}/ublk.err" &
    DAEMON_PID=$!
    MODE="ublk"

    for _ in $(seq 100); do
        # The daemon also logs to stdout, so match the device path line.
        DEV_PATH=$(grep -m1 -E '^/dev/ublkb[0-9]+$' "$out" || true)
        [[ -n "$DEV_PATH" && -b "$DEV_PATH" ]] && break
        sleep 0.1
    done
    [[ -b "$DEV_PATH" ]] || { echo "ublk device did not appear" >&2; cat "${WORKDIR}/ublk.err" >&2; exit 1; }
    mount -t erofs -o ro "$DEV_PATH" "$MNT"
}

mount_fuse() {
    "$NYDUS_BIN" fuse --bootstrap "$BOOTSTRAP" --config "$CONFIG" --mountpoint "$MNT" \
        >"${WORKDIR}/fuse.out" 2>"${WORKDIR}/fuse.err" &
    DAEMON_PID=$!
    MODE="fuse"

    for _ in $(seq 100); do
        mountpoint -q "$MNT" && return
        sleep 0.1
    done
    echo "fuse mount did not appear" >&2
    cat "${WORKDIR}/fuse.err" >&2
    exit 1
}

record() { echo "$1,$2,$3,$4" >> "$OUTPUT"; }

# P1: metadata-heavy walk, the container cold-start pattern.
bench_metadata() {
    local impl=$1 run=$2
    local start end
    start=$(date +%s.%N)
    find "$MNT" -type f -exec stat {} + > /dev/null
    end=$(date +%s.%N)
    record "$impl" "$run" "metadata_walk_secs" "$(echo "$end - $start" | bc)"
}

# P2/P3: fio data path, reported as IOPS and bandwidth.
#
# The mount is read-only, so fio cannot lay out its own files: point it at the
# largest regular files already in the image instead.
fio_targets() {
    find "$MNT" -type f -size +16M -printf '%s %p\n' 2>/dev/null |
        sort -rn | head -"$1" | cut -d' ' -f2- | paste -sd:
}

bench_fio() {
    local impl=$1 run=$2 name=$3 rw=$4 bs=$5 jobs=$6
    local json="${WORKDIR}/fio-${impl}-${name}-${run}.json"
    local targets
    targets=$(fio_targets "$jobs")
    [[ -n "$targets" ]] || { echo "no file large enough for fio in $MNT" >&2; exit 1; }

    # Both paths let the kernel cache file data, so every phase has to start
    # from the same cold state or whichever runs second wins on cache alone.
    sync && echo 3 > /proc/sys/vm/drop_caches

    fio --name="$name" --filename="$targets" --rw="$rw" --bs="$bs" --numjobs="$jobs" \
        --size="$FIO_SIZE" \
        --iodepth=32 --ioengine=psync --runtime="$FIO_RUNTIME" --time_based \
        --readonly --group_reporting --output-format=json --output="$json" > /dev/null
    record "$impl" "$run" "${name}_iops" "$(jq '.jobs[0].read.iops' "$json")"
    record "$impl" "$run" "${name}_bw_kbps" "$(jq '.jobs[0].read.bw' "$json")"
}

bench_impl() {
    local impl=$1 run=$2
    case "$impl" in
        ublk) mount_ublk ;;
        fuse) mount_fuse ;;
    esac

    sync && echo 3 > /proc/sys/vm/drop_caches
    bench_metadata "$impl" "$run"
    # P2 4K random read and P3 1M sequential read.
    bench_fio "$impl" "$run" "randread_4k" "randread" "4k" 1
    bench_fio "$impl" "$run" "seqread_1m" "read" "1m" 1
    # P5 concurrency.
    bench_fio "$impl" "$run" "randread_4k_x${JOBS}" "randread" "4k" "$JOBS"

    cleanup
}

echo "impl,run,metric,value" > "$OUTPUT"
for run in $(seq "$RUNS"); do
    for impl in ublk fuse; do
        echo "=== run ${run}: ${impl} ==="
        bench_impl "$impl" "$run"
    done
done

echo
echo "results written to ${OUTPUT}"
column -s, -t < "$OUTPUT"
