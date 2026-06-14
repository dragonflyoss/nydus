#!/usr/bin/env bash
#
# Resolve and extract the Nydus bootstrap (image.boot) for a Nydus image.
#
# Inputs (env):
#   NYDUS_IMAGE   full image reference, e.g. ghcr.io/foo/bar:nydus-latest
#   PLATFORM      OCI platform selector for index manifests (e.g. linux/amd64)
#   WORK_DIR      scratch directory
#
# Output:
#   On success, writes the bootstrap blob to "$WORK_DIR/bootstrap" and prints
#   that path to stdout.
#
# Notes:
#   The bootstrap is identified by the layer annotation
#     containerd.io/snapshot/nydus-bootstrap=true
#   and falls back to "the first non-blob nydus layer" if the annotation is
#   missing (matches the convention used in the repo's e2e workflow).
#   The blob is a tar.gz containing image.boot (or *.boot) which is what
#   nydusd actually consumes.
set -euo pipefail

: "${NYDUS_IMAGE:?NYDUS_IMAGE must be set}"
: "${WORK_DIR:?WORK_DIR must be set}"
PLATFORM="${PLATFORM:-linux/amd64}"

mkdir -p "${WORK_DIR}"
MANIFEST="${WORK_DIR}/manifest.json"
LAYER_TGZ="${WORK_DIR}/bootstrap-layer.tar.gz"
EXTRACT_DIR="${WORK_DIR}/bootstrap-extract"
OUT="${WORK_DIR}/bootstrap"

echo "[fetch-bootstrap] image=${NYDUS_IMAGE} platform=${PLATFORM}" >&2

crane manifest --platform "${PLATFORM}" "${NYDUS_IMAGE}" > "${MANIFEST}"

# Identify the bootstrap layer. Prefer the explicit annotation, then fall
# back to the first layer whose mediaType mentions "nydus" but not "blob"
# (matches the convention used in this repo's e2e workflow).
BOOTSTRAP_DIGEST=$(jq -r '
    (.layers[]?
       | select(.annotations["containerd.io/snapshot/nydus-bootstrap"] == "true")
       | .digest) // (
    .layers[]?
       | select((.mediaType // "") | (contains("nydus") and (contains("blob") | not)))
       | .digest)
' "${MANIFEST}" | head -n1)

if [ -z "${BOOTSTRAP_DIGEST}" ] || [ "${BOOTSTRAP_DIGEST}" = "null" ]; then
    echo "[fetch-bootstrap] ERROR: no bootstrap layer in manifest" >&2
    cat "${MANIFEST}" >&2
    exit 1
fi

echo "[fetch-bootstrap] bootstrap layer digest=${BOOTSTRAP_DIGEST}" >&2
crane blob "${NYDUS_IMAGE}@${BOOTSTRAP_DIGEST}" > "${LAYER_TGZ}"

rm -rf "${EXTRACT_DIR}"
mkdir -p "${EXTRACT_DIR}"
if ! tar -xf "${LAYER_TGZ}" -C "${EXTRACT_DIR}" 2>/dev/null; then
    echo "[fetch-bootstrap] ERROR: failed to untar bootstrap layer" >&2
    file "${LAYER_TGZ}" >&2 || true
    exit 1
fi

BOOTSTRAP_FILE=$(find "${EXTRACT_DIR}" \( -name 'image.boot' -o -name '*.boot' \) -type f | head -1)
if [ -z "${BOOTSTRAP_FILE}" ]; then
    echo "[fetch-bootstrap] ERROR: no .boot file in extracted layer" >&2
    find "${EXTRACT_DIR}" >&2
    exit 1
fi

cp "${BOOTSTRAP_FILE}" "${OUT}"
echo "[fetch-bootstrap] wrote ${OUT} ($(stat -c%s "${OUT}") bytes)" >&2
echo "${OUT}"
