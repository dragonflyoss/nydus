#!/usr/bin/env bash
# Waits until the Dragonfly cluster started by cluster.sh actually serves:
# manager health, scheduler and seed-peer gRPC health, and a byte-exact P2P
# download through the dfdaemon proxy. Usage: wait-ready.sh [seconds]
set -euo pipefail
exec "$(dirname "${BASH_SOURCE[0]}")/cluster.sh" wait-ready "$@"
