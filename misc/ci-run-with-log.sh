#!/usr/bin/env bash

set -uo pipefail

if [ "$#" -lt 2 ]; then
    echo "Usage: ci-run-with-log.sh LOG_FILE COMMAND [ARG ...]" >&2
    exit 64
fi

log_file=$1
shift

set +e
"$@" 2>&1 | tee -- "$log_file"
pipeline_status=("${PIPESTATUS[@]}")
status=${pipeline_status[0]}
if [ "$status" -eq 0 ]; then
    status=${pipeline_status[1]}
fi

if [ "$status" -ne 0 ]; then
    # Keep failures visible on the check page even when full logs are unavailable.
    python3 - "$log_file" "$status" <<'PY' || true
from collections import deque
import re
import sys

try:
    with open(sys.argv[1], encoding="utf-8", errors="replace") as log:
        excerpt = "".join(deque(log, maxlen=30))
except OSError:
    excerpt = "The command log could not be read."

excerpt = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", excerpt)[-2400:]
excerpt = excerpt.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
print(f"::error title=Smoke command failed::Exit status {sys.argv[2]}; log excerpt:%0A{excerpt}")
PY
fi

exit "$status"
