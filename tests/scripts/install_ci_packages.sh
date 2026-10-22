#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
	echo "usage: $0 package..." >&2
	exit 2
fi

# Hosted x86 runners put Azure first in this mirror list. A stalled Azure
# download can spend minutes retrying before reaching the same Ubuntu archive.
# Leave self-hosted and ARM sources untouched.
if [[ ${RUNNER_ENVIRONMENT:-} == github-hosted && -f /etc/apt/apt-mirrors.txt ]]; then
	sudo sed -i 's|http://azure.archive.ubuntu.com/ubuntu|https://archive.ubuntu.com/ubuntu|g' /etc/apt/apt-mirrors.txt
fi

options=(-o Acquire::Retries=2 -o Acquire::http::Timeout=10 -o Acquire::https::Timeout=10)
sudo apt-get "${options[@]}" update -qq
sudo apt-get "${options[@]}" install -y --no-install-recommends "$@"
