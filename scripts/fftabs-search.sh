#!/bin/bash
# Search Firefox tabs by URL or title pattern
# Usage: fftabs-search.sh <pattern>

if [ -z "$1" ]; then
    echo "Usage: fftabs-search.sh <pattern>" >&2
    exit 1
fi

PATTERN="$1"

ffsclient tabs list --format json | jq --arg p "$PATTERN" \
    '[.[] | {device: .client, tabs: [.tabs[] | select((.title // "") + " " + (.urlHistory[0] // "") | test($p; "i"))]} | select(.tabs | length > 0)]'
