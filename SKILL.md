---
name: firefox-tabs
description: Access and control Firefox synced tabs across all devices. List tabs from any synced device, search by URL or title, send tabs to devices, and close remote tabs. Use when finding open tabs, sending URLs to other devices, or closing tabs remotely. Requires ffsclient authentication and Python 3.
metadata:
  openclaw:
    requires:
      bins: [ffsclient, python3]
---

# Firefox Tabs

Access and control your Firefox synced tabs from the command line.

## Quick Start

```bash
# List all tabs from all devices
./scripts/fftabs-list.sh

# Search for tabs matching a pattern
./scripts/fftabs-search.sh "github"

# Send a URL to another device
./scripts/fftabs-send.sh "Laptop" "https://example.com" "Example Site"

# List devices with command capabilities
./scripts/fftabs-cmd-devices.sh
```

## Commands

### Read-only Commands (via ffsclient)

| Command | Description |
|---------|-------------|
| `fftabs-list.sh` | List all synced tabs as JSON |
| `fftabs-devices.sh` | List all synced device names |
| `fftabs-search.sh <pattern>` | Search tabs by URL or title (case-insensitive) |
| `fftabs-check-auth.sh` | Verify Firefox Sync authentication |

### Remote Control Commands (via FxA Device Commands API)

| Command | Description |
|---------|-------------|
| `fftabs-cmd-devices.sh [--json]` | List devices with command capabilities |
| `fftabs-send.sh <device> <url> [title]` | Send URL to open on a device |
| `fftabs-close.sh <device> <url> [url2...]` | Close specific tabs on a device |
| `fftabs-close-matching.sh <pattern> [--device X]` | Close tabs matching URL pattern |

## Device Matching

Device names use **partial, case-insensitive matching**:
- `"Laptop"` matches "Your Firefox on Laptop"
- `"phone"` matches "My Phone" or "Work Phone"
- `"server"` matches "Your Firefox on hostname"

Use `fftabs-cmd-devices.sh` to see exact device names.

## Device Capabilities

Not all devices support all commands:

```
$ ./scripts/fftabs-cmd-devices.sh
Laptop (desktop): send-tab, close-tabs
Phone (mobile): send-tab
Tablet (tablet): send-tab, close-tabs
Firefox-Sync-Client on server (cli): (current)
```

- **send-tab**: Device can receive tabs (most Firefox installations)
- **close-tabs**: Device supports remote tab closing (Firefox 133+)
- **(current)**: The CLI device - cannot send to itself

## Examples

### Send a tab to your laptop
```bash
./scripts/fftabs-send.sh "Laptop" "https://news.ycombinator.com" "Hacker News"
```

### Send a tab to any matching device
```bash
./scripts/fftabs-send.sh "phone" "https://example.com"
```

### Close all Reddit tabs on your laptop
```bash
./scripts/fftabs-close-matching.sh "reddit.com" --device "Laptop"
```

### Find which device has a specific tab open
```bash
./scripts/fftabs-search.sh "github.com/myrepo"
```

## Direct Python Usage

The underlying Python library can be used directly:

```bash
# List devices with JSON output
python3 lib/fftabs_cmd.py --json devices

# Send a tab
python3 lib/fftabs_cmd.py send "Device Name" "https://url" --title "Title"

# Close tabs
python3 lib/fftabs_cmd.py close "Device Name" "https://url1" "https://url2"
```

## Setup

See [references/setup.md](references/setup.md) for authentication instructions.

## Technical Details

### Authentication
- Uses ffsclient session stored at `~/.config/firefox-sync-client.secret`
- Session contains OAuth tokens and keyB for encryption
- Remote commands use HAWK authentication with the FxA API

### Encryption
Remote tab commands use proper end-to-end encryption:
1. Sync key derived from keyB using HKDF
2. Device public keys decrypted from `availableCommands`
3. Payloads encrypted using Web Push (RFC 8188 aes128gcm)
4. Each device has unique ECDH keypair for receiving commands

### API Endpoints
- Tabs list: Firefox Sync storage API
- Device commands: `api.accounts.firefox.com/v1/account/devices/invoke_command`
