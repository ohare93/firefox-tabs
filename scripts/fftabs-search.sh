#!/usr/bin/env bash
# Search Firefox tabs by URL or title pattern
# Usage: fftabs-search.sh <pattern>

if [ -z "$1" ]; then
    echo "Usage: fftabs-search.sh <pattern>" >&2
    exit 1
fi

PATTERN="$1"

ffsclient tabs list --format json | jq --arg p "$PATTERN" \
    '[.[] | select((.title // "") + " " + (.urlHistory[0] // "") | test($p; "i"))] | group_by(.client_name) | map({device: .[0].client_name, tabs: [.[] | {title: .title, url: .urlHistory[0]}]})'
