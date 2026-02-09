---
name: firefox-tabs
description: Access Firefox synced tabs across all devices. List tabs from any synced device, search by URL or title, view recently accessed pages. Use when finding open tabs, locating a page across devices, or reviewing browsing activity. Requires ffsclient and Firefox Sync authentication.
metadata:
  openclaw:
    requires:
      bins: [ffsclient]
---

# Firefox Tabs

Access your Firefox synced tabs from the command line.

## Quick Start

```bash
# List all tabs from all devices
./scripts/fftabs-list.sh

# List synced devices
./scripts/fftabs-devices.sh

# Search for tabs matching a pattern
./scripts/fftabs-search.sh "github"

# Check authentication status
./scripts/fftabs-check-auth.sh
```

## Commands

| Command | Description |
|---------|-------------|
| `fftabs-list.sh` | List all synced tabs as JSON |
| `fftabs-devices.sh` | List all synced device names |
| `fftabs-search.sh <pattern>` | Search tabs by URL or title (case-insensitive) |
| `fftabs-check-auth.sh` | Verify Firefox Sync authentication |

## Setup

See [references/setup.md](references/setup.md) for authentication instructions.

## Output Format

### List Output

Returns JSON array of devices with their tabs:

```json
[
  {
    "client": "Desktop",
    "tabs": [
      {
        "title": "Example Page",
        "urlHistory": ["https://example.com"],
        "icon": "...",
        "lastUsed": 1707500000
      }
    ]
  }
]
```

### Search Output

Returns filtered devices with only matching tabs:

```json
[
  {
    "device": "Laptop",
    "tabs": [
      {
        "title": "GitHub - Project",
        "urlHistory": ["https://github.com/..."]
      }
    ]
  }
]
```
