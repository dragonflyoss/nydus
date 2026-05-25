#!/bin/bash

set -euo pipefail

# Usage: bash misc/install-protoc.sh [arch] [system]
#   arch:   amd64, arm64, ppc64le  (default: auto-detect)
#   system: linux, osx             (default: auto-detect)

PROTOC_VERSION="29.6"

ARCH="${1:-}"
SYSTEM="${2:-}"

# Auto-detect system if not provided
if [ -z "$SYSTEM" ]; then
    case "$(uname -s)" in
        Linux)  SYSTEM="linux" ;;
        Darwin) SYSTEM="osx" ;;
        *)      echo "Unsupported OS: $(uname -s)" >&2; exit 1 ;;
    esac
fi

# Auto-detect arch if not provided
if [ -z "$ARCH" ]; then
    case "$(uname -m)" in
        x86_64)          ARCH="amd64" ;;
        aarch64|arm64)   ARCH="arm64" ;;
        ppc64le)         ARCH="ppc64le" ;;
	riscv64)         ARCH="riscv64" ;;
        *)               echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
    esac
fi

# Map to protobuf release naming
case "$ARCH" in
    amd64)   PROTOC_ARCH="x86_64" ;;
    arm64)   PROTOC_ARCH="aarch_64" ;;
    ppc64le) PROTOC_ARCH="ppcle_64" ;;
    riscv64) echo "Skipping protoc install for riscv64 (unsupported)"; exit 0 ;;
    *)       echo "Unsupported arch: $ARCH (expected amd64, arm64, ppc64le)" >&2; exit 1 ;;
esac

ZIPFILE="protoc-${PROTOC_VERSION}-${SYSTEM}-${PROTOC_ARCH}.zip"
URL="https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/${ZIPFILE}"

echo "Installing protoc ${PROTOC_VERSION} for ${SYSTEM}-${PROTOC_ARCH}"
curl -sLO "$URL"
sudo unzip -o "$ZIPFILE" -d /usr/local
rm "$ZIPFILE"
