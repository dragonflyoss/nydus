#!/usr/bin/env bash
#
# Nydus + Dragonfly SDK proxy perf-test orchestrator.
#
# Phases:
#   1. Resolve the nydusd config:
#        - If $NYDUSD_CONFIG points to an existing file, use it as-is.
#        - Otherwise, render /etc/nydus/config.template.json with envsubst.
#   2. Resolve the bootstrap:
#        - If $BOOTSTRAP_PATH is set and exists, use it.
#        - Otherwise, fetch from $NYDUS_IMAGE via crane (see fetch-bootstrap).
#   3. Start /usr/local/bin/nydusd in FUSE mode with --apisock for telemetry.
#   4. Wait for FUSE to be mounted AND nydusd to report state RUNNING.
#   5. Run the parallel-read workload over $MOUNT_POINT.
#   6. Scrape nydusd metrics and emit a JSON summary to $RESULTS_DIR/result.json.
#   7. Unmount and exit cleanly.
set -euo pipefail

log() { printf '[perftest] %s\n' "$*" >&2; }
die() { printf '[perftest] ERROR: %s\n' "$*" >&2; exit 1; }

is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

endpoint_host() {
    local endpoint="$1"
    local authority host

    [ -n "${endpoint}" ] || return 1
    authority="${endpoint#*://}"
    authority="${authority%%/*}"
    if [[ "${authority}" == \[*\]* ]]; then
        host="${authority#\[}"
        host="${host%%\]*}"
    else
        host="${authority%%:*}"
    fi
    [ -n "${host}" ] || return 1
    printf '%s\n' "${host}"
}

resolve_ipv4() {
    local host="$1"
    local ip=""

    if is_ipv4 "${host}"; then
        printf '%s\n' "${host}"
        return 0
    fi

    if command -v getent >/dev/null 2>&1; then
        ip="$(getent ahostsv4 "${host}" 2>/dev/null | awk 'NR == 1 {print $1}' || true)"
    fi
    if [ -z "${ip}" ] && command -v nslookup >/dev/null 2>&1; then
        ip="$(nslookup "${host}" 2>/dev/null | awk '
            /^Address[[:space:]]+[0-9]+: / {print $3; exit}
            /^Address: / && $2 !~ /:53$/ {print $2; exit}
        ' || true)"
    fi
    [ -n "${ip}" ] || return 1
    printf '%s\n' "${ip}"
}

ensure_default_ipv4_route() {
    local endpoint host ip route gateway="" dev=""
    local -a fields

    command -v ip >/dev/null 2>&1 || {
        log "ip command not found; skipping default route workaround"
        return
    }
    [ -z "$(ip -4 route show default 2>/dev/null)" ] || return

    log "No default IPv4 route found; trying to derive one from reachable endpoints"
    for endpoint in "${DRAGONFLY_SCHEDULER_ENDPOINT}" "${DRAGONFLY_PROXY_URL}" "${REGISTRY_HOST:-}"; do
        host="$(endpoint_host "${endpoint}" 2>/dev/null || true)"
        [ -n "${host}" ] || continue
        ip="$(resolve_ipv4 "${host}" 2>/dev/null || true)"
        [ -n "${ip}" ] || {
            log "Could not resolve IPv4 address for ${host}; skipping"
            continue
        }

        route="$(ip -4 route get "${ip}" 2>/dev/null || true)"
        route="${route%%$'\n'*}"
        [ -n "${route}" ] || {
            log "No IPv4 route to ${host} (${ip}); skipping"
            continue
        }

        fields=(${route})
        gateway=""
        dev=""
        for ((i = 0; i < ${#fields[@]}; i++)); do
            case "${fields[$i]}" in
                via)
                    gateway="${fields[$((i + 1))]:-}"
                    ;;
                dev)
                    dev="${fields[$((i + 1))]:-}"
                    ;;
            esac
        done

        [ -n "${dev}" ] || {
            log "Route to ${host} (${ip}) has no device: ${route}"
            continue
        }

        if [ -n "${gateway}" ]; then
            if ip route add default via "${gateway}" dev "${dev}" 2>/dev/null; then
                log "Added default IPv4 route via ${gateway} dev ${dev} (derived from ${host}/${ip})"
                return
            fi
        elif ip route add default dev "${dev}" 2>/dev/null; then
            log "Added default IPv4 route dev ${dev} (derived from ${host}/${ip})"
            return
        fi
        log "Failed to add default route from ${host}/${ip}: ${route}"
    done

    log "No default IPv4 route could be derived; Dragonfly SDK local IP discovery may fail"
}

# ---- Inputs ----------------------------------------------------------------
NYDUS_IMAGE="${NYDUS_IMAGE:-}"
NYDUSD_CONFIG="${NYDUSD_CONFIG:-}"
BOOTSTRAP_PATH="${BOOTSTRAP_PATH:-}"
MOUNT_POINT="${MOUNT_POINT:-/mnt/nydus}"
RESULTS_DIR="${RESULTS_DIR:-/results}"
WORK_DIR="${WORK_DIR:-/tmp/nydus}"
BLOB_CACHE_DIR="${BLOB_CACHE_DIR:-/var/lib/nydus/cache}"
READ_PARALLELISM="${READ_PARALLELISM:-16}"
READ_CHUNK_SIZE="${READ_CHUNK_SIZE:-1048576}"
MAX_FILES="${MAX_FILES:-0}"
MOUNT_READY_TIMEOUT="${MOUNT_READY_TIMEOUT:-60}"
NYDUSD_LOG_LEVEL="${NYDUSD_LOG_LEVEL:-info}"
PLATFORM="${PLATFORM:-linux/amd64}"

DRAGONFLY_PROXY_URL="${DRAGONFLY_PROXY_URL:-http://host.docker.internal:4001}"
DRAGONFLY_SCHEDULER_ENDPOINT="${DRAGONFLY_SCHEDULER_ENDPOINT:-http://host.docker.internal:8002}"
REGISTRY_SCHEME="${REGISTRY_SCHEME:-https}"
REGISTRY_AUTH="${REGISTRY_AUTH:-}"
REGISTRY_SKIP_VERIFY="${REGISTRY_SKIP_VERIFY:-false}"
PROXY_FALLBACK="${PROXY_FALLBACK:-true}"
ENABLE_DEFAULT_ROUTE_WORKAROUND="${ENABLE_DEFAULT_ROUTE_WORKAROUND:-false}"
DIGEST_VALIDATE="${DIGEST_VALIDATE:-false}"
PREFETCH_ENABLE="${PREFETCH_ENABLE:-false}"
PREFETCH_THREADS="${PREFETCH_THREADS:-8}"
STREAM_PREFETCH="${STREAM_PREFETCH:-false}"
STREAM_PREFETCH_THREADS="${STREAM_PREFETCH_THREADS:-5}"
STREAM_PREFETCH_BANDWIDTH="${STREAM_PREFETCH_BANDWIDTH:-0}"
STREAM_PREFETCH_MAX_RETRY="${STREAM_PREFETCH_MAX_RETRY:-10}"
NYDUSD="/usr/local/bin/nydusd"

mkdir -p "${WORK_DIR}" "${RESULTS_DIR}" "${BLOB_CACHE_DIR}" "${MOUNT_POINT}"

if [ ! -x "${NYDUSD}" ]; then
    die "nydusd is not executable: ${NYDUSD}"
fi
if ! NYDUSD_VERSION="$("${NYDUSD}" --version 2>&1 | tr '\n' ' ')"; then
    die "failed to execute ${NYDUSD}: ${NYDUSD_VERSION}"
fi
log "Using nydusd binary: ${NYDUSD} (${NYDUSD_VERSION})"

# If REGISTRY_AUTH is provided (base64 of "user:password"), materialise a
# docker config.json so `crane` (used by fetch-bootstrap) can authenticate
# against private registries. The nydusd registry backend already picks up
# REGISTRY_AUTH via the rendered config below.
if [ -n "${REGISTRY_AUTH}" ]; then
    auth_host="${REGISTRY_HOST:-}"
    if [ -z "${auth_host}" ] && [ -n "${NYDUS_IMAGE}" ]; then
        ref="${NYDUS_IMAGE%@*}"; ref="${ref%:*}"
        if [[ "${ref}" == */* ]]; then
            first="${ref%%/*}"
            if [[ "${first}" == *.* || "${first}" == *:* || "${first}" == "localhost" ]]; then
                auth_host="${first}"
            fi
        fi
        auth_host="${auth_host:-docker.io}"
    fi
    export DOCKER_CONFIG="${WORK_DIR}/.docker"
    mkdir -p "${DOCKER_CONFIG}"
    jq -n --arg host "${auth_host}" --arg auth "${REGISTRY_AUTH}" \
        '{auths: {($host): {auth: $auth}}}' \
        > "${DOCKER_CONFIG}/config.json"
    chmod 600 "${DOCKER_CONFIG}/config.json"
    log "Wrote registry credentials for ${auth_host} to ${DOCKER_CONFIG}/config.json"
fi

APISOCK="${WORK_DIR}/api.sock"
NYDUSD_LOG="${WORK_DIR}/nydusd.log"
RESULT_JSON="${RESULTS_DIR}/result.json"

# ---- Phase 1: resolve config ----------------------------------------------
if [ -n "${NYDUSD_CONFIG}" ] && [ -f "${NYDUSD_CONFIG}" ]; then
    CONFIG_PATH="${NYDUSD_CONFIG}"
    log "Using user-supplied nydusd config: ${CONFIG_PATH}"
else
    [ -n "${NYDUS_IMAGE}" ] || die "either NYDUSD_CONFIG or NYDUS_IMAGE must be set"

    # Parse NYDUS_IMAGE into REGISTRY_HOST and REGISTRY_REPO. The first path
    # segment is the host iff it contains '.' or ':' or equals 'localhost';
    # otherwise we default to docker.io with the 'library/' prefix when only
    # a single name segment is present (matching docker's reference parser).
    REF="${NYDUS_IMAGE%@*}"
    REF="${REF%:*}"
    if [[ "${REF}" == */* ]]; then
        first="${REF%%/*}"; rest="${REF#*/}"
        if [[ "${first}" == *.* || "${first}" == *:* || "${first}" == "localhost" ]]; then
            REGISTRY_HOST="${REGISTRY_HOST:-${first}}"
            REGISTRY_REPO="${REGISTRY_REPO:-${rest}}"
        else
            REGISTRY_HOST="${REGISTRY_HOST:-docker.io}"
            REGISTRY_REPO="${REGISTRY_REPO:-${REF}}"
        fi
    else
        REGISTRY_HOST="${REGISTRY_HOST:-docker.io}"
        REGISTRY_REPO="${REGISTRY_REPO:-library/${REF}}"
    fi
    export REGISTRY_HOST REGISTRY_REPO REGISTRY_SCHEME REGISTRY_AUTH \
           REGISTRY_SKIP_VERIFY PROXY_FALLBACK \
           DRAGONFLY_PROXY_URL DRAGONFLY_SCHEDULER_ENDPOINT \
           BLOB_CACHE_DIR DIGEST_VALIDATE PREFETCH_ENABLE PREFETCH_THREADS \
           STREAM_PREFETCH STREAM_PREFETCH_THREADS STREAM_PREFETCH_BANDWIDTH \
           STREAM_PREFETCH_MAX_RETRY

    CONFIG_PATH="${WORK_DIR}/nydusd.json"
    envsubst < /etc/nydus/config.template.json > "${CONFIG_PATH}"
    log "Rendered config -> ${CONFIG_PATH}"
    log "  registry: ${REGISTRY_SCHEME}://${REGISTRY_HOST}/${REGISTRY_REPO}"
    log "  proxy:    ${DRAGONFLY_PROXY_URL}  scheduler: ${DRAGONFLY_SCHEDULER_ENDPOINT}"
fi
if [ "${ENABLE_DEFAULT_ROUTE_WORKAROUND}" = "true" ]; then
    ensure_default_ipv4_route
else
    log "Default IPv4 route workaround disabled"
fi

# ---- Phase 2: resolve bootstrap -------------------------------------------
if [ -n "${BOOTSTRAP_PATH}" ] && [ -f "${BOOTSTRAP_PATH}" ]; then
    log "Using user-supplied bootstrap: ${BOOTSTRAP_PATH}"
else
    [ -n "${NYDUS_IMAGE}" ] || die "BOOTSTRAP_PATH not set and NYDUS_IMAGE empty; cannot fetch bootstrap"
    log "Fetching bootstrap from ${NYDUS_IMAGE} (platform=${PLATFORM})"
    BOOTSTRAP_PATH="$(NYDUS_IMAGE="${NYDUS_IMAGE}" PLATFORM="${PLATFORM}" \
                      WORK_DIR="${WORK_DIR}" /usr/local/bin/fetch-bootstrap)"
fi

# ---- Phase 3: start nydusd -------------------------------------------------
log "Starting nydusd: binary=${NYDUSD} bootstrap=${BOOTSTRAP_PATH} mountpoint=${MOUNT_POINT}"
T_DAEMON_START=$(date +%s.%N)

"${NYDUSD}" \
    --config "${CONFIG_PATH}" \
    --bootstrap "${BOOTSTRAP_PATH}" \
    --mountpoint "${MOUNT_POINT}" \
    --apisock "${APISOCK}" \
    --log-level "${NYDUSD_LOG_LEVEL}" \
    > "${NYDUSD_LOG}" 2>&1 &
NYDUSD_PID=$!

cleanup() {
    rc=$?
    log "Cleanup (rc=${rc})"
    if mountpoint -q "${MOUNT_POINT}" 2>/dev/null; then
        umount "${MOUNT_POINT}" 2>/dev/null || umount -l "${MOUNT_POINT}" 2>/dev/null || true
    fi
    if kill -0 "${NYDUSD_PID}" 2>/dev/null; then
        kill "${NYDUSD_PID}" 2>/dev/null || true
        wait "${NYDUSD_PID}" 2>/dev/null || true
    fi
    if [ "${rc}" -ne 0 ] && [ -f "${NYDUSD_LOG}" ]; then
        log "--- nydusd.log (tail) ---"
        tail -n 80 "${NYDUSD_LOG}" >&2 || true
    fi
}
trap cleanup EXIT

# ---- Phase 4: wait for readiness ------------------------------------------
log "Waiting up to ${MOUNT_READY_TIMEOUT}s for FUSE mount and daemon RUNNING state..."
T_MOUNT_READY=""
deadline=$(( $(date +%s) + MOUNT_READY_TIMEOUT ))
while [ "$(date +%s)" -lt "${deadline}" ]; do
    if ! kill -0 "${NYDUSD_PID}" 2>/dev/null; then
        die "nydusd exited prematurely (see ${NYDUSD_LOG})"
    fi
    if mountpoint -q "${MOUNT_POINT}" && [ -S "${APISOCK}" ]; then
        state=$(nydusctl --sock "${APISOCK}" --raw info 2>/dev/null \
                | jq -r '.state // ""' 2>/dev/null || true)
        if [ "${state}" = "RUNNING" ] || [ "${state}" = "Running" ]; then
            T_MOUNT_READY=$(date +%s.%N); break
        fi
    fi
    sleep 0.2
done
[ -n "${T_MOUNT_READY}" ] || die "timed out waiting for nydusd to become RUNNING"

MOUNT_READY_SEC=$(awk -v a="${T_MOUNT_READY}" -v b="${T_DAEMON_START}" 'BEGIN{printf "%.3f", a-b}')
log "Mount ready in ${MOUNT_READY_SEC}s"

# ---- Phase 5: workload -----------------------------------------------------
log "Running workload (parallelism=${READ_PARALLELISM}, chunk=${READ_CHUNK_SIZE} bytes, max_files=${MAX_FILES})"
WORKLOAD_OUT="${WORK_DIR}/workload.json"
T_WORKLOAD_START=$(date +%s.%N)
set +e
workload \
    --root "${MOUNT_POINT}" \
    --parallelism "${READ_PARALLELISM}" \
    --chunk-size "${READ_CHUNK_SIZE}" \
    --max-files "${MAX_FILES}" \
    --output "${WORKLOAD_OUT}"
WORKLOAD_RC=$?
set -e
T_WORKLOAD_END=$(date +%s.%N)
WORKLOAD_SEC=$(awk -v a="${T_WORKLOAD_END}" -v b="${T_WORKLOAD_START}" 'BEGIN{printf "%.3f", a-b}')
log "Workload finished in ${WORKLOAD_SEC}s (rc=${WORKLOAD_RC})"

# ---- Phase 6: scrape metrics + emit summary -------------------------------
# Each scrape must produce valid JSON for jq's --slurpfile to work.
scrape() {
    local out
    out=$(nydusctl --sock "${APISOCK}" --raw "$@" 2>/dev/null) || out=""
    if [ -z "${out}" ] || ! printf '%s' "${out}" | jq -e . >/dev/null 2>&1; then
        echo "{}"
    else
        printf '%s' "${out}"
    fi
}
echo "$(scrape info)"            > "${WORK_DIR}/info.json"
echo "$(scrape metrics backend)" > "${WORK_DIR}/backend.json"
echo "$(scrape metrics cache)"   > "${WORK_DIR}/cache.json"
echo "$(scrape metrics fsstats)" > "${WORK_DIR}/fsstats.json"

[ -f "${WORKLOAD_OUT}" ] || echo '{}' > "${WORKLOAD_OUT}"

jq -n \
    --arg image            "${NYDUS_IMAGE:-}" \
    --arg platform         "${PLATFORM}" \
    --arg config_path      "${CONFIG_PATH}" \
    --arg bootstrap_path   "${BOOTSTRAP_PATH}" \
    --arg nydusd_bin       "${NYDUSD}" \
    --arg nydusd_version   "${NYDUSD_VERSION}" \
    --arg proxy_url        "${DRAGONFLY_PROXY_URL}" \
    --arg scheduler        "${DRAGONFLY_SCHEDULER_ENDPOINT}" \
    --argjson proxy_fb     "$([ "${PROXY_FALLBACK}" = "true" ] && echo true || echo false)" \
    --argjson mount_ready  "${MOUNT_READY_SEC}" \
    --argjson workload_sec "${WORKLOAD_SEC}" \
    --argjson workload_rc  "${WORKLOAD_RC}" \
    --slurpfile workload   "${WORKLOAD_OUT}" \
    --slurpfile info       "${WORK_DIR}/info.json" \
    --slurpfile backend    "${WORK_DIR}/backend.json" \
    --slurpfile blobcache  "${WORK_DIR}/cache.json" \
    --slurpfile fs         "${WORK_DIR}/fsstats.json" \
    '{
        image:           $image,
        platform:        $platform,
        config_path:     $config_path,
        bootstrap_path:  $bootstrap_path,
        dragonfly: { proxy_url: $proxy_url, scheduler_endpoint: $scheduler, proxy_fallback: $proxy_fb },
        timing_sec:      { mount_ready: $mount_ready, workload: $workload_sec },
        workload_rc:     $workload_rc,
        workload:        ($workload[0] // {}),
        nydusd: {
            binary:    $nydusd_bin,
            version:   $nydusd_version,
            info:      ($info[0]      // {}),
            backend:   ($backend[0]   // {}),
            blobcache: ($blobcache[0] // {}),
            fs:        ($fs[0]        // {})
        }
     }' > "${RESULT_JSON}"

log "Wrote summary to ${RESULT_JSON}"
echo "================ PERF TEST SUMMARY ================" >&2
jq -r '
  "image            : \(.image)",
  "nydusd_binary    : \(.nydusd.binary)",
  "nydusd_version   : \(.nydusd.version)",
  "mount_ready_sec  : \(.timing_sec.mount_ready)",
  "workload_sec     : \(.timing_sec.workload)",
  "files_read       : \(.workload.files_read // 0)  (skipped=\(.workload.files_skipped // 0), errors=\(.workload.files_errored // 0))",
  "bytes_read       : \(.workload.bytes_read // 0)",
  "throughput_MBps  : \(.workload.throughput_mbps // 0)",
  "latency_ms p50/p95/p99 : \(.workload.latency_ms.p50 // 0) / \(.workload.latency_ms.p95 // 0) / \(.workload.latency_ms.p99 // 0)",
  "workload_rc      : \(.workload_rc)"
' "${RESULT_JSON}" >&2
echo "===================================================" >&2

exit "${WORKLOAD_RC}"
