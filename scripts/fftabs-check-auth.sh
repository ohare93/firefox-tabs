#!/usr/bin/env bash
# Check Firefox Sync authentication status

if ffsclient collections &>/dev/null; then
    echo "Authenticated"
else
    echo "Not authenticated. Run: ffsclient login <email>"
    exit 1
fi
