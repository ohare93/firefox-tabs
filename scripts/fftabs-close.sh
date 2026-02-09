#!/usr/bin/env bash
# Close specific tabs on a remote Firefox device
# Usage: fftabs-close.sh <device-name> <url> [url2] [url3] ...

set -e

if [ -z "$2" ]; then
    echo "Usage: fftabs-close.sh <device-name> <url> [url2] [url3] ..." >&2
    echo "" >&2
    echo "Arguments:" >&2
    echo "  device-name  Name of the target device (partial match)" >&2
    echo "  url          One or more URLs to close on the device" >&2
    exit 1
fi

DEVICE="$1"
shift

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

python3 "$SCRIPT_DIR/../lib/fftabs_cmd.py" close "$DEVICE" "$@"
