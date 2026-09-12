#!/bin/bash
set -u

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 OUTPUT_DIRECTORY [DURATION_SECONDS]" >&2
  exit 2
fi

output_dir=$1
duration=${2:-40}
mkdir -p "$output_dir"
sudo -v || exit 1

interfaces=${INTERFACES:-"en8 en10 en11 awdl0 llw0"}
pids=""

cleanup() {
  for pid in $pids; do
    sudo -n pkill -INT -P "$pid" 2>/dev/null || true
    kill -INT "$pid" 2>/dev/null || true
  done
  for pid in $pids; do
    wait "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

for interface in $interfaces; do
  if ifconfig "$interface" >/dev/null 2>&1; then
    # -G/-W makes tcpdump itself exit, avoiding a sudo wrapper that outlives
    # the requested capture duration.
    sudo tcpdump -i "$interface" -s 0 -U -n -G "$duration" -W 1 \
      -w "$output_dir/$interface.pcap" \
      > "$output_dir/$interface.tcpdump.log" 2>&1 &
    pids="$pids $!"
  fi
done

for pid in $pids; do
  wait "$pid"
done
pids=""
