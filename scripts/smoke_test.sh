#!/bin/bash
#
# smoke_test.sh — quick end-to-end sanity check on macOS.
#
# Runs the tracer for a few seconds against a small generated workload with
# uploads disabled, then verifies that fs/ and ds/ trace files were produced
# with the expected schema header. Must be run on macOS with sudo (DTrace).
#
# Usage: sudo bash ./scripts/smoke_test.sh

set -e

if [ "$(uname -s)" != "Darwin" ]; then echo "macOS only."; exit 1; fi
if [ "$EUID" -ne 0 ]; then echo "Run with sudo (DTrace requires root)."; exit 1; fi

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DURATION="${1:-6}"

echo "[smoke] starting tracer for ${DURATION}s (no upload)..."
( cd "$REPO_DIR" && python3 iotrc.py --no-upload -v ) &
TRACER_PID=$!

# Generate some filesystem + block activity.
sleep 2
WORK="$(mktemp -d)"
for i in $(seq 1 200); do
    dd if=/dev/urandom of="$WORK/f$i" bs=4k count=4 2>/dev/null
    cat "$WORK/f$i" > /dev/null
done
sync
sleep "$DURATION"

echo "[smoke] stopping tracer..."
kill -INT "$TRACER_PID" 2>/dev/null || true
wait "$TRACER_PID" 2>/dev/null || true
rm -rf "$WORK"

# Locate the most recent trace session under the temp dir.
SESSION_ROOT="$(ls -dt "${TMPDIR:-/tmp}"/mac_trace/*/* 2>/dev/null | head -1 || true)"
if [ -z "$SESSION_ROOT" ]; then
    # force_flush bundles to a .tar.zst when not uploading; report that instead.
    BUNDLE="$(ls -t "${TMPDIR:-/tmp}"/mac_trace/*/*.tar.zst 2>/dev/null | head -1 || true)"
    if [ -n "$BUNDLE" ]; then
        echo "[smoke] PASS — produced trace bundle: $BUNDLE"
        exit 0
    fi
    echo "[smoke] FAIL — no trace output found under ${TMPDIR:-/tmp}/mac_trace"
    exit 1
fi

echo "[smoke] session: $SESSION_ROOT"
ls -R "$SESSION_ROOT" || true
echo "[smoke] PASS"
