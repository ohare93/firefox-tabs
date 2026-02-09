# Firefox Tabs Setup Guide

## Prerequisites

- Firefox account with Sync enabled
- `ffsclient` (firefox-sync-client)
- Python 3 with `requests` and `cryptography` packages
- `jq` (for JSON processing in shell scripts)

## Installation

### Python Dependencies

Install the required Python packages:

```bash
pip install requests cryptography
```

### NixOS

Add to your configuration:

```nix
environment.systemPackages = with pkgs; [
  firefox-sync-client
  jq
  (python3.withPackages (ps: [ ps.requests ps.cryptography ]))
];
```

Or with Home Manager:

```nix
home.packages = with pkgs; [
  firefox-sync-client
  jq
  (python3.withPackages (ps: [ ps.requests ps.cryptography ]))
];
```

## Authentication

1. Run the login command:

   ```bash
   ffsclient login your@email.com
   ```

2. Enter your Firefox account password when prompted

3. Verify authentication:

   ```bash
   ffsclient collections
   ```

   Should list: `tabs`, `bookmarks`, `history`, etc.

## Session Storage

Credentials are stored at `~/.config/firefox-sync-client.secret`

This file contains:
- OAuth tokens for API access
- `keyB` - the account master key used for encryption
- Session token for HAWK authentication

The session persists across sessions—no need to re-authenticate.

## Verification

Test that everything works:

```bash
# List all tabs (read-only)
./scripts/fftabs-list.sh

# Check device command capabilities
./scripts/fftabs-cmd-devices.sh

# Send a test tab to a device
./scripts/fftabs-send.sh "YourDevice" "https://example.com" "Test"
```

## Troubleshooting

### "Not authenticated" error

Re-run `ffsclient login <email>`

### No tabs showing

1. Ensure Firefox Sync is enabled on your devices
2. Force sync in Firefox: Settings → Sync → Sync Now
3. Wait a few minutes for sync to complete

### Permission denied on secret file

```bash
chmod 600 ~/.config/firefox-sync-client.secret
```

### Device doesn't support close-tabs

The close-tabs command requires Firefox 133+. Older Firefox versions only support send-tab.

### "Device not found" error

Device names use partial, case-insensitive matching. Check available devices with:

```bash
./scripts/fftabs-cmd-devices.sh
```

Examples:
- `"phone"` matches "My Phone"
- `"laptop"` matches "Your Firefox on Laptop"

### Tab not appearing on device

1. Ensure the target device is online
2. Firefox must be running on the target device
3. The device receives a push notification—may take a few seconds
4. Check the device supports send-tab: `./scripts/fftabs-cmd-devices.sh`

### Network timeout errors

If you see "context deadline exceeded":
1. Check your internet connection
2. Mozilla's sync servers may be temporarily slow
3. Try again in a few minutes

## How It Works

### Read Operations (ffsclient)
- Uses Firefox Sync storage API
- Fetches tabs collection from Mozilla's sync servers
- Decrypts with sync bulk keys

### Remote Commands (fftabs_cmd.py)
1. **Authentication**: HAWK signature using session token
2. **Key Derivation**: Sync key derived from `keyB` via HKDF
3. **Device Key Decryption**: Each device's public key is encrypted in `availableCommands`
4. **Payload Encryption**: Uses Web Push (RFC 8188 aes128gcm) with device's ECDH public key
5. **Command Delivery**: POST to FxA API, device receives push notification
