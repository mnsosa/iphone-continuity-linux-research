#!/bin/bash
set -u

if [[ $# -ne 2 ]]; then
  echo "usage: $0 OUTPUT_FILE DURATION_SECONDS" >&2
  exit 2
fi

output=$1
duration=$2
end=$((SECONDS + duration))

while (( SECONDS < end )); do
  {
    echo "===== $(date -u '+%Y-%m-%dT%H:%M:%S.%NZ') ====="
    netstat -ibn
    lsof -nP -iTCP -iUDP
    ps -axo pid,ppid,command
  } >> "$output" 2>&1
  sleep 1
done
