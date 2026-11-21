#!/bin/bash

set -euo pipefail

: "${GITHUB_OUTPUT:?GITHUB_OUTPUT must point to the step output file}"

release_base=https://github.com/dragonflyoss/nydus/releases
source "$(dirname "${BASH_SOURCE[0]}")/github-release.sh"
stable_version=$(github_latest_stable_tag "$release_base")

download_dir=$(mktemp -d)
trap 'rm -rf "$download_dir"' EXIT

versions=(v0.1.0 "$stable_version")
version_archs=(v0.1.0-x86_64 "$stable_version-linux-amd64")
for i in "${!versions[@]}"; do
    version=${versions[$i]}
    archive="nydus-static-${version_archs[$i]}.tgz"
    echo "Preparing Nydus $version"
    curl --fail --silent --show-error --location --retry 3 \
        --output "$download_dir/$archive" "$release_base/download/$version/$archive"
    mkdir -p "$download_dir/$version"
    tar xzf "$download_dir/$archive" -C "$download_dir/$version"
    sudo mkdir -p "/usr/bin/nydus-$version"
    sudo cp -r "$download_dir/$version/nydus-static/." "/usr/bin/nydus-$version/"
done

# Keep the selected release consistent with the binaries used by later steps.
printf 'stable-version=%s\n' "$stable_version" >> "$GITHUB_OUTPUT"
