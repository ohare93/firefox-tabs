# Firefox Tabs Setup Guide

## Prerequisites

- Firefox account with Sync enabled
- `ffsclient` (firefox-sync-client)

## Installation

### NixOS

Add to your configuration:

```nix
environment.systemPackages = with pkgs; [
  firefox-sync-client
];
```

Or with Home Manager:

```nix
home.packages = with pkgs; [
  firefox-sync-client
];
```

### Quick Test

```bash
nix-shell -p firefox-sync-client
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

This persists across sessions—no need to re-authenticate.

## Verification

Test that everything works:

```bash
# List all tabs
ffsclient tabs list

# JSON format for parsing
ffsclient tabs list --format json
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
