#!/bin/bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
source_file="$repo/macos-probe/Sources/main.swift"
app="$repo/macos-probe/build/ContinuityCameraProbe.app"
contents="$app/Contents"

mkdir -p "$contents/MacOS"
xcrun swiftc \
  -parse-as-library \
  -framework AVFoundation \
  -framework CoreMedia \
  -framework CoreVideo \
  "$source_file" \
  -o "$contents/MacOS/ContinuityCameraProbe"
cp "$repo/macos-probe/Info.plist" "$contents/Info.plist"
codesign --force --sign - "$app"
echo "$app"
