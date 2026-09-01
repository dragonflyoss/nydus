#!/bin/bash
# publish-crates.sh — Publish the nydus workspace crates to crates.io in
# dependency order, skipping crate versions that are already published.
#
# Usage:
#   ./scripts/publish-crates.sh --dry-run   # verify packaging only, no upload
#   ./scripts/publish-crates.sh             # confirm, then publish
#   ./scripts/publish-crates.sh --yes       # publish without confirmation
#
# Requires a crates.io token (`cargo login` or CARGO_REGISTRY_TOKEN).

set -euo pipefail

PROJ_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJ_DIR"

# Dependency order: every crate appears after all workspace crates it uses.
CRATES=(
    nydus-format
    nydus-telemetry
    nydus-error
    nydus-config
    nydus-backend
    nydus-storage
    nydus-core
    nydus
)

DRY_RUN=0
ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -y|--yes)  ASSUME_YES=1 ;;
        *) echo "usage: $0 [--dry-run] [--yes]" >&2; exit 2 ;;
    esac
done

crate_version() {
    sed -n 's/^version = "\(.*\)"/\1/p' "$1/Cargo.toml" | head -1
}

# True if name@version is already in the crates.io sparse index.
published() {
    local name=$1 version=$2
    local prefix="${name:0:2}/${name:2:2}" # index layout for names >= 4 chars
    curl -fsSL "https://index.crates.io/${prefix}/${name}" 2>/dev/null |
        grep -qF "\"vers\":\"${version}\""
}

if [[ -n "$(git status --porcelain)" ]]; then
    echo "error: working tree is dirty; commit or stash before publishing" >&2
    exit 1
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
    # Packages the whole workspace and verifies inter-dependent crates against
    # the packaged (not yet published) sources; nothing is uploaded.
    cargo package --workspace
    exit 0
fi

echo "About to publish to crates.io:"
for crate in "${CRATES[@]}"; do
    version="$(crate_version "$crate")"
    if published "$crate" "$version"; then
        echo "  ${crate}@${version} (already published, will skip)"
    else
        echo "  ${crate}@${version}"
    fi
done

if [[ "$ASSUME_YES" -ne 1 ]]; then
    read -r -p "Continue? [y/N] " answer
    [[ "$answer" == [yY] ]] || { echo "aborted" >&2; exit 1; }
fi

for crate in "${CRATES[@]}"; do
    version="$(crate_version "$crate")"
    if published "$crate" "$version"; then
        echo "==> ${crate}@${version} already on crates.io, skipping"
        continue
    fi
    echo "==> publishing ${crate}@${version}"
    # cargo blocks until the new version is visible in the index, so each
    # later crate in the list can resolve the ones published before it.
    cargo publish -p "$crate"
done

echo "All crates published."

