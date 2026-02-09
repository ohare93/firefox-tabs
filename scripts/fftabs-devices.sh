#!/bin/bash
# List all synced Firefox devices

ffsclient tabs list --format json | jq -r '.[].client' | sort -u
