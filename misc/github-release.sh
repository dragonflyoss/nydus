#!/bin/bash

github_latest_stable_tag() {
    local release_base=$1 release_url tag
    # Use the public redirect so parallel CI jobs don't share a REST API quota.
    release_url=$(curl --fail --silent --show-error --location --head --retry 3 \
        --output /dev/null --write-out '%{url_effective}' "$release_base/latest") || return
    tag=${release_url##*/}
    if [[ "$release_url" != "$release_base/tag/$tag" || \
          ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Invalid stable release URL: $release_url" >&2
        return 1
    fi
    printf '%s\n' "$tag"
}
