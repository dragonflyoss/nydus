#!/usr/bin/env bash

set -uo pipefail

if [ "$#" -lt 2 ]; then
    echo "Usage: ci-run-with-log.sh LOG_FILE COMMAND [ARG ...]" >&2
    exit 64
fi

log_file=$1
shift

# Keep streaming the original output and preserve a failing command's status.
# If the command succeeds, a logging failure must still fail the step.
set +e
"$@" 2>&1 | tee -- "$log_file"
pipeline_status=("${PIPESTATUS[@]}")
command_status=${pipeline_status[0]}
if [ "$command_status" -eq 0 ]; then
    command_status=${pipeline_status[1]}
fi

if [ "$command_status" -ne 0 ]; then
    python3 - "$log_file" "$command_status" <<'PY' || true
from collections import deque
import re
import sys

try:
    with open(sys.argv[1], encoding="utf-8", errors="replace", newline="") as log:
        summary = "".join(deque(log, maxlen=60))
except OSError:
    summary = "The command log could not be read."

# Annotations are a short diagnostic excerpt, without a new environment or
# command-line dump. Strip terminal formatting before escaping workflow data.
summary = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", summary)
summary = summary[-12000:] or "The command produced no output."
escapes = {"%": "%25", "\r": "%0D", "\n": "%0A"}
parts = []
size = 0
for char in reversed(summary):
    part = escapes.get(char, char)
    if size + len(part) > 11800:
        break
    parts.append(part)
    size += len(part)

escaped = "".join(reversed(parts))
print(f"::error title=CI command failed::Exit status {sys.argv[2]}; last log lines:%0A{escaped}")
PY
fi

exit "$command_status"
