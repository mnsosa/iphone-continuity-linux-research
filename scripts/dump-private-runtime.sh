#!/bin/bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
binary="$repo/macos-probe/build/runtime-dump"
mkdir -p "$repo/macos-probe/build" "$repo/dumps"
xcrun clang -fobjc-arc -framework Foundation "$repo/macos-probe/runtime-dump.m" -o "$binary"
"$binary" > "$repo/dumps/private-runtime.txt"
echo "$repo/dumps/private-runtime.txt"
