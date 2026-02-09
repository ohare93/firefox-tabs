#!/usr/bin/env bash
# Close tabs matching a pattern on remote Firefox devices
# Usage: fftabs-close-matching.sh <pattern> [--device <device-name>]

set -e

if [ -z "$1" ]; then
    echo "Usage: fftabs-close-matching.sh <pattern> [--device <device-name>]" >&2
    echo "" >&2
    echo "Arguments:" >&2
    echo "  pattern     URL pattern to match (case-insensitive substring)" >&2
    echo "  --device    Optional: limit to specific device (partial match)" >&2
    echo "" >&2
    echo "Examples:" >&2
    echo "  fftabs-close-matching.sh reddit.com" >&2
    echo "  fftabs-close-matching.sh twitter.com --device Laptop" >&2
    exit 1
fi

PATTERN="$1"
DEVICE=""

shift
while [ $# -gt 0 ]; do
    case "$1" in
        --device|-d)
            DEVICE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Get all tabs and filter by pattern
TABS=$(ffsclient tabs list --format json 2>/dev/null)

# Filter, group by device, and output one JSON object per line (compact)
GROUPED=$(echo "$TABS" | jq -c --arg p "$PATTERN" --arg d "$DEVICE" '
[.[] |
select(
    ($d == "" or (.client_name | ascii_downcase | contains($d | ascii_downcase)))
) |
select(
    ((.title // "") + " " + (.urlHistory[0] // "")) | ascii_downcase | contains($p | ascii_downcase)
) |
{
    device: .client_name,
    url: .urlHistory[0],
    title: .title
}] |
group_by(.device) |
map({
    device: .[0].device,
    urls: [.[].url]
}) |
.[]
')

if [ -z "$GROUPED" ]; then
    echo "No matching tabs found for pattern: $PATTERN"
    exit 0
fi

# Process each device (one JSON object per line)
echo "$GROUPED" | while IFS= read -r line; do
    DEVICE_NAME=$(echo "$line" | jq -r '.device')

    # Get URLs as newline-separated list
    URLS=$(echo "$line" | jq -r '.urls[]')

    if [ -n "$URLS" ] && [ -n "$DEVICE_NAME" ]; then
        echo "Closing tabs on $DEVICE_NAME matching '$PATTERN':"
        echo "$URLS" | while IFS= read -r url; do
            echo "  - $url"
        done

        # Close the tabs - convert newlines to arguments
        # shellcheck disable=SC2086
        echo "$URLS" | xargs python3 "$SCRIPT_DIR/../lib/fftabs_cmd.py" close "$DEVICE_NAME" 2>/dev/null || echo "Warning: Could not close tabs on $DEVICE_NAME (device may not support close-tabs command)"
    fi
done
