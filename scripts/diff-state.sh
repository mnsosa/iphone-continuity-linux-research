#!/bin/bash
set -u

if [[ $# -ne 2 ]]; then
  echo "usage: $0 BEFORE_PHASE_DIRECTORY AFTER_PHASE_DIRECTORY" >&2
  exit 2
fi

before=$1
after=$2
for before_file in "$before"/*.txt; do
  name=$(basename "$before_file")
  after_file="$after/$name"
  if [[ -f "$after_file" ]]; then
    echo "===== $name ====="
    diff -u "$before_file" "$after_file" || true
  fi
done
