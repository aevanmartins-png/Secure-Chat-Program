#!/bin/sh

set -eu

echo "checking files"
if [ ! -s .git/HEAD ]; then
  echo "error: execute this script in the directory where your .git directory is" >&2
  exit 1
fi

makefile="$(find -name Makefile | grep -Fv '/.git/' | head -n1)"
if [ ! -s "$makefile" ]; then
  echo "error: missing or empty file Makefile" >&2
  exit 1
fi

d="$(dirname "$makefile")"
for f in README.md group.txt ttp.sh; do
  if [ ! -s "$d/$f" ]; then
    echo "error: missing or empty file: $f" >&2
    exit 1
  fi
done

if ! grep -q '|' "$d/group.txt"; then
  echo "error: no group member lines in group.txt" >&2
  exit 1
fi

if grep '|' "$d/group.txt" | LC_ALL=C grep -Evq '^ *[0-9]+ *\| *[A-Za-z][A-Za-z][A-Za-z][0-9][0-9][0-9] *\|[^\|]+\|[^\|]+@[^\|]+$'; then
  echo "error: invalid member line(s) in group.txt" >&2
  exit 1
fi

echo "cleaning up"
if ! make -C "$d" clean > /dev/null 2>&1; then
  echo "error: make clean failed" >&2
  exit 1
fi

echo "checking build output"
if ! make -C "$d" all > /dev/null 2>&1; then
  echo "error: make all failed" >&2
  exit 1
fi

for f in client server; do
  if [ ! -x "$d/$f" ]; then
    echo "error: missing or empty file (after make clean all): $f" >&2
    exit 1
  fi
done

echo "checking cleanup"
if ! make -C "$d" clean > /dev/null 2>&1; then
  echo "error: make clean failed (second time)" >&2
  exit 1
fi

for f in clientkeys serverkeys ttpkeys; do
  if [ -d "$d/$f" ]; then
    echo "error: directory not removed by make clean: $f" >&2
    exit 1
  fi
done

for f in chat.db client server; do
  if [ -f "$d/$f" ]; then
    echo "error: file not removed by make clean: $f" >&2
    exit 1
  fi
done

echo "building archive"
tar --exclude=asg1-submission.tgz --exclude=test-tmp --warning=no-file-changed -czf asg1-submission.tgz ./
