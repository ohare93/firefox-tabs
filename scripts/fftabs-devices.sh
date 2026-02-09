#!/usr/bin/env bash
# List all synced Firefox devices

ffsclient tabs list --format json | jq -r '.[].client_name' | sort -u
