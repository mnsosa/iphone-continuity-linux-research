#!/bin/bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
app="$repo/macos-probe/build/ContinuityCameraProbe.app"
binary="$app/Contents/MacOS/ContinuityCameraProbe"
run_id=$(date -u '+%Y%m%dT%H%M%SZ')
run_dir="$repo/experiments/runs/$run_id"
markers="$run_dir/markers"
mkdir -p "$run_dir/network" "$run_dir/states" "$markers"

if [[ ! -x "$binary" ]]; then
  "$repo/scripts/build-probe.sh"
fi

sudo -v
"$repo/scripts/snapshot-system.sh" "$run_dir/states" idle >/dev/null
"$repo/scripts/capture-network.sh" "$run_dir/network" 42 &
capture_pid=$!
"$repo/scripts/monitor-state.sh" "$run_dir/state-monitor.log" 42 &
monitor_pid=$!
sudo /usr/bin/log stream --style compact --level debug \
  --predicate 'process == "remoted" OR process == "ContinuityCaptureAgent" OR process == "rapportd" OR process == "usbmuxd" OR process == "iOSScreenCaptureAssistant" OR subsystem CONTAINS[c] "ContinuityCapture" OR subsystem CONTAINS[c] "CoreMediaIO"' \
  > "$run_dir/unified.log" 2>&1 &
log_pid=$!

cleanup() {
  sudo kill -INT "$log_pid" 2>/dev/null || true
  kill "$monitor_pid" 2>/dev/null || true
  kill "$capture_pid" 2>/dev/null || true
  wait "$log_pid" 2>/dev/null || true
  wait "$monitor_pid" 2>/dev/null || true
  wait "$capture_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

sleep 2
"$binary" --markers-dir "$markers" > "$run_dir/probe.jsonl" 2> "$run_dir/probe.stderr.log" &
probe_pid=$!

wait_marker() {
  local marker=$1
  while [[ ! -f "$markers/$marker" ]] && kill -0 "$probe_pid" 2>/dev/null; do
    sleep 0.1
  done
}

wait_marker discovered
"$repo/scripts/snapshot-system.sh" "$run_dir/states" discovered >/dev/null
wait_marker streaming
"$repo/scripts/snapshot-system.sh" "$run_dir/states" streaming >/dev/null
wait "$probe_pid"
"$repo/scripts/snapshot-system.sh" "$run_dir/states" stopped >/dev/null
wait "$capture_pid" || true

sudo kill -INT "$log_pid" 2>/dev/null || true
kill "$monitor_pid" 2>/dev/null || true
wait "$log_pid" 2>/dev/null || true
wait "$monitor_pid" 2>/dev/null || true
trap - EXIT INT TERM

"$repo/scripts/diff-state.sh" "$run_dir/states/idle" "$run_dir/states/streaming" \
  > "$run_dir/idle-to-streaming.diff"
echo "$run_dir"
