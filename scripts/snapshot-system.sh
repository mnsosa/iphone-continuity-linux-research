#!/bin/bash
set -u

if [[ $# -ne 2 ]]; then
  echo "usage: $0 OUTPUT_DIRECTORY LABEL" >&2
  exit 2
fi

output_dir=$1
label=$2
if [[ ! "$label" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "label may only contain letters, numbers, dot, underscore, and dash" >&2
  exit 2
fi

phase_dir="$output_dir/$label"
mkdir -p "$phase_dir"
date -u '+%Y-%m-%dT%H:%M:%S.%NZ' > "$phase_dir/timestamp.txt"

run() {
  local name=$1
  shift
  "$@" > "$phase_dir/$name.txt" 2>&1 || true
}

run system-profiler-usb system_profiler SPUSBDataType -detailLevel full
run ioreg-usb ioreg -p IOUSB -l -w0
run ioreg-iphone ioreg -r -n iPhone -l -w0
run ioreg-ethernet ioreg -r -c IOEthernetInterface -l -w0
run ifconfig ifconfig -a
run hardware-ports networksetup -listallhardwareports
run routes-ipv4 netstat -rn -f inet
run routes-ipv6 netstat -rn -f inet6
run interface-counters netstat -ibn
run arp arp -an
run neighbors-ipv6 ndp -an
run network-state scutil --nwi
run sockets lsof -nP -iTCP -iUDP
run processes ps -axo pid,ppid,user,lstart,command

printf '%s\n' "$phase_dir"
