#!/usr/bin/env bash
# Send a URL to a remote Firefox device
# Usage: fftabs-send.sh <device-name> <url> [title]

set -e

if [ -z "$2" ]; then
    echo "Usage: fftabs-send.sh <device-name> <url> [title]" >&2
    echo "" >&2
    echo "Arguments:" >&2
    echo "  device-name  Name of the target device (partial match)" >&2
    echo "  url          URL to open on the device" >&2
    echo "  title        Optional title for the tab" >&2
    exit 1
fi

DEVICE="$1"
URL="$2"
TITLE="${3:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -n "$TITLE" ]; then
    python3 "$SCRIPT_DIR/../lib/fftabs_cmd.py" send "$DEVICE" "$URL" --title "$TITLE"
else
    python3 "$SCRIPT_DIR/../lib/fftabs_cmd.py" send "$DEVICE" "$URL"
fi
