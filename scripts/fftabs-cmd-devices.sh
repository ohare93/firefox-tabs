#!/usr/bin/env bash
# List devices with their command capabilities (send-tab, close-tabs)
# Usage: fftabs-cmd-devices.sh [--json]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$1" = "--json" ] || [ "$1" = "-j" ]; then
    python3 "$SCRIPT_DIR/../lib/fftabs_cmd.py" --json devices
else
    python3 "$SCRIPT_DIR/../lib/fftabs_cmd.py" devices
fi
