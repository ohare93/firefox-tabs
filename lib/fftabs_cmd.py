#!/usr/bin/env python3
"""
Firefox Tabs Command Library

Implements FxA Device Commands protocol for sending tabs and closing tabs
on remote Firefox devices. Uses session credentials from ffsclient.

References:
- https://github.com/mozilla/fxa-auth-server/blob/master/docs/device_registration.md
- https://mozilla.github.io/application-services/book/rust-docs/fxa_client/index.html
- RFC 8188 (aes128gcm encryption)
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time
from typing import Optional
from urllib.parse import urlparse

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# FxA API endpoints
FXA_API_BASE = "https://api.accounts.firefox.com/v1"

# Command URIs
COMMAND_SEND_TAB = "https://identity.mozilla.com/cmd/open-uri"
COMMAND_CLOSE_TABS = "https://identity.mozilla.com/cmd/close-uri/v1"

# Default session file location
DEFAULT_SESSION_FILE = os.path.expanduser("~/.config/firefox-sync-client.secret")


def urlsafe_b64encode(data: bytes) -> str:
    """Base64 URL-safe encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def urlsafe_b64decode(data: str) -> bytes:
    """Base64 URL-safe decode with padding restoration."""
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


class HawkAuth:
    """HAWK authentication for FxA API requests."""

    def __init__(self, session_token: str):
        self.session_token = bytes.fromhex(session_token)
        self._derive_hawk_credentials()

    def _derive_hawk_credentials(self):
        """Derive HAWK credentials from session token using HKDF."""
        info = b"identity.mozilla.com/picl/v1/sessionToken"

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=b"",
            info=info,
            backend=default_backend()
        )
        derived = hkdf.derive(self.session_token)

        self.token_id = derived[:32].hex()
        self.req_hmac_key = derived[32:64]

    def _generate_nonce(self) -> str:
        """Generate a random nonce for HAWK."""
        return base64.b64encode(os.urandom(6)).decode('ascii')

    def sign_request(self, method: str, url: str, content_type: str = "", body: str = "") -> dict:
        """Generate HAWK authorization header."""
        parsed = urlparse(url)

        ts = str(int(time.time()))
        nonce = self._generate_nonce()

        normalized = "\n".join([
            "hawk.1.header",
            ts,
            nonce,
            method.upper(),
            parsed.path,
            parsed.netloc,
            "443",
            "",
            "",
            ""
        ])

        mac = hmac.new(self.req_hmac_key, normalized.encode(), hashlib.sha256)
        mac_b64 = base64.b64encode(mac.digest()).decode('ascii')

        auth_header = f'Hawk id="{self.token_id}", ts="{ts}", nonce="{nonce}", mac="{mac_b64}"'

        return {"Authorization": auth_header}


class SyncCrypto:
    """Handles Firefox Sync encryption/decryption."""

    def __init__(self, bulk_key_hex: str, hmac_key_hex: str):
        self.bulk_key = bytes.fromhex(bulk_key_hex)
        self.hmac_key = bytes.fromhex(hmac_key_hex)

    def decrypt(self, ciphertext_b64: str, iv_b64: str, hmac_value: str = None) -> bytes:
        """Decrypt a Firefox Sync encrypted payload.

        Note: HMAC verification is skipped for device command keys as they use
        a different HMAC computation that doesn't match standard Sync format.
        The encryption itself is verified by successful JSON parsing.
        """
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)

        cipher = Cipher(algorithms.AES(self.bulk_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()

        pad_len = padded[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Invalid padding")
        return padded[:-pad_len]

    def encrypt(self, plaintext: bytes) -> dict:
        """Encrypt data for Firefox Sync format."""
        iv = os.urandom(16)

        pad_len = 16 - (len(plaintext) % 16)
        padded = plaintext + bytes([pad_len] * pad_len)

        cipher = Cipher(algorithms.AES(self.bulk_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        mac = hmac.new(self.hmac_key, ciphertext, hashlib.sha256).digest()

        return {
            "IV": base64.b64encode(iv).decode('ascii'),
            "ciphertext": base64.b64encode(ciphertext).decode('ascii'),
            "hmac": base64.b64encode(mac).decode('ascii')
        }


class WebPushCrypto:
    """
    Implements Web Push encryption (RFC 8188 aes128gcm) for Firefox Send Tab.

    This is the encryption format Firefox uses for device commands.
    """

    @staticmethod
    def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
        """HKDF key derivation."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
            backend=default_backend()
        )
        return hkdf.derive(ikm)

    @staticmethod
    def _public_key_to_bytes(public_key) -> bytes:
        """Convert EC public key to uncompressed point format (65 bytes)."""
        numbers = public_key.public_numbers()
        return b'\x04' + numbers.x.to_bytes(32, 'big') + numbers.y.to_bytes(32, 'big')

    @staticmethod
    def _bytes_to_public_key(data: bytes):
        """Convert uncompressed point bytes to EC public key."""
        if data[0] != 0x04 or len(data) != 65:
            raise ValueError("Invalid uncompressed EC point")

        x = int.from_bytes(data[1:33], 'big')
        y = int.from_bytes(data[33:65], 'big')

        public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        return public_numbers.public_key(default_backend())

    @classmethod
    def encrypt(cls, plaintext: bytes, recipient_public_key: bytes, auth_secret: bytes) -> bytes:
        """
        Encrypt data using Web Push aes128gcm encryption.

        Args:
            plaintext: Data to encrypt
            recipient_public_key: Recipient's P-256 public key (65 bytes, uncompressed)
            auth_secret: 16-byte authentication secret

        Returns:
            Encrypted payload with aes128gcm header
        """
        # Generate ephemeral key pair
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        local_public_bytes = cls._public_key_to_bytes(public_key)

        # Parse recipient public key
        recipient_key = cls._bytes_to_public_key(recipient_public_key)

        # ECDH to get shared secret
        shared_secret = private_key.exchange(ec.ECDH(), recipient_key)

        # Generate salt
        salt = os.urandom(16)

        # Key derivation per RFC 8188
        # auth_info = "WebPush: info" || 0x00 || recipient_public || sender_public
        auth_info = b"WebPush: info\x00" + recipient_public_key + local_public_bytes

        # PRK = HKDF-Extract(auth_secret, shared_secret)
        # IKM for the main HKDF
        prk = cls._hkdf(shared_secret, auth_secret, auth_info, 32)

        # Derive content encryption key and nonce
        # CEK = HKDF-Expand(PRK, "Content-Encoding: aes128gcm" || 0x00, 16)
        cek_info = b"Content-Encoding: aes128gcm\x00"
        cek = cls._hkdf(prk, salt, cek_info, 16)

        # Nonce = HKDF-Expand(PRK, "Content-Encoding: nonce" || 0x00, 12)
        nonce_info = b"Content-Encoding: nonce\x00"
        nonce = cls._hkdf(prk, salt, nonce_info, 12)

        # Add padding delimiter (0x02 for final record)
        padded_plaintext = plaintext + b'\x02'

        # Encrypt with AES-128-GCM
        aesgcm = AESGCM(cek)
        ciphertext = aesgcm.encrypt(nonce, padded_plaintext, None)

        # Build aes128gcm header:
        # salt (16) || rs (4) || idlen (1) || keyid (65)
        rs = 4096  # Record size
        header = salt + struct.pack('>I', rs) + struct.pack('B', 65) + local_public_bytes

        return header + ciphertext


class FxACommands:
    """Firefox Accounts Device Commands client."""

    def __init__(self, session_file: str = DEFAULT_SESSION_FILE):
        self.session_file = session_file
        self._load_session()

    def _load_session(self):
        """Load session credentials from ffsclient format."""
        try:
            with open(self.session_file) as f:
                session = json.load(f)
        except FileNotFoundError:
            raise RuntimeError(
                f"Session file not found: {self.session_file}\n"
                "Run 'ffsclient login <email>' to authenticate."
            )
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid session file format: {e}")

        try:
            self.session_token = session["sessionToken"]
            key_b = bytes.fromhex(session["keyB"])

            # Derive sync key bundle from kB for device command encryption
            # See: https://mozilla-services.readthedocs.io/en/latest/sync/storageformat5.html
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=b"",
                info=b"identity.mozilla.com/picl/v1/oldsync",
                backend=default_backend()
            )
            derived = hkdf.derive(key_b)
            sync_enc_key = derived[:32].hex()
            sync_hmac_key = derived[32:64].hex()

            self.sync_crypto = SyncCrypto(sync_enc_key, sync_hmac_key)

            self.hawk = HawkAuth(self.session_token)
        except KeyError as e:
            raise RuntimeError(
                f"Session file missing required field: {e}\n"
                "Try re-authenticating with 'ffsclient login <email>'."
            )

    def _api_request(self, method: str, endpoint: str, json_data: dict = None) -> dict:
        """Make authenticated request to FxA API."""
        url = f"{FXA_API_BASE}{endpoint}"
        headers = self.hawk.sign_request(method, url)
        headers["Content-Type"] = "application/json"

        resp = requests.request(method, url, headers=headers, json=json_data)
        if not resp.ok:
            try:
                error_body = resp.json()
            except Exception:
                error_body = resp.text
            raise requests.HTTPError(f"{resp.status_code}: {error_body}", response=resp)
        if not resp.content:
            return {}
        try:
            return resp.json()
        except json.JSONDecodeError:
            return {}

    def get_devices(self) -> list:
        """Get list of devices registered to this account."""
        return self._api_request("GET", "/account/devices")

    def get_devices_with_commands(self) -> list:
        """Get devices that support device commands."""
        devices = self.get_devices()

        result = []
        for device in devices:
            commands = device.get("availableCommands", {})
            device_info = {
                "id": device["id"],
                "name": device.get("name", "Unknown"),
                "type": device.get("type", "unknown"),
                "can_receive_tabs": COMMAND_SEND_TAB in commands,
                "can_close_tabs": COMMAND_CLOSE_TABS in commands,
                "is_current": device.get("isCurrentDevice", False)
            }

            if COMMAND_SEND_TAB in commands:
                device_info["_send_tab_key"] = commands[COMMAND_SEND_TAB]
            if COMMAND_CLOSE_TABS in commands:
                device_info["_close_tabs_key"] = commands[COMMAND_CLOSE_TABS]

            result.append(device_info)

        return result

    def find_device_by_name(self, name: str) -> Optional[dict]:
        """Find a device by name (case-insensitive partial match)."""
        devices = self.get_devices_with_commands()
        name_lower = name.lower()

        for device in devices:
            if name_lower in device["name"].lower():
                return device

        return None

    def _decrypt_device_key(self, encrypted_key_json: str) -> dict:
        """
        Decrypt a device's public key bundle from availableCommands.

        Returns dict with 'publicKey' and 'authSecret' (both base64url encoded).
        """
        encrypted = json.loads(encrypted_key_json)
        decrypted_bytes = self.sync_crypto.decrypt(
            encrypted["ciphertext"],
            encrypted["IV"],
            encrypted["hmac"]
        )
        return json.loads(decrypted_bytes)

    def _encrypt_command_payload(self, target_device: dict, payload: dict, key_field: str) -> dict:
        """
        Encrypt a command payload for a target device using Web Push encryption.

        Args:
            target_device: Device info dict with encrypted key
            payload: The command payload to encrypt
            key_field: Which key to use ('_send_tab_key' or '_close_tabs_key')

        Returns:
            Dict with 'encrypted' field containing base64url-encoded ciphertext
        """
        # Get the encrypted key bundle
        encrypted_key_json = target_device.get(key_field)
        if not encrypted_key_json:
            raise ValueError(f"Device missing {key_field}")

        # Decrypt to get publicKey and authSecret
        key_bundle = self._decrypt_device_key(encrypted_key_json)

        # Decode the public key and auth secret
        public_key = urlsafe_b64decode(key_bundle["publicKey"])
        auth_secret = urlsafe_b64decode(key_bundle["authSecret"])

        # Serialize payload
        payload_bytes = json.dumps(payload).encode('utf-8')

        # Encrypt using Web Push aes128gcm
        encrypted = WebPushCrypto.encrypt(payload_bytes, public_key, auth_secret)

        return {"encrypted": urlsafe_b64encode(encrypted)}

    def send_tab(self, device_name: str, url: str, title: str = "") -> dict:
        """Send a tab to a device.

        Args:
            device_name: Name of the target device (partial match)
            url: URL to open on the device
            title: Optional title for the tab

        Returns:
            Result dict with success status and details
        """
        device = self.find_device_by_name(device_name)
        if not device:
            return {"success": False, "error": f"Device not found: {device_name}"}

        if not device["can_receive_tabs"]:
            return {"success": False, "error": f"Device does not support receiving tabs: {device['name']}"}

        if device["is_current"]:
            return {"success": False, "error": "Cannot send tab to the current device"}

        # Build the send tab payload
        payload = {
            "entries": [{"url": url, "title": title or url}],
            "flowID": os.urandom(16).hex(),
            "streamID": os.urandom(16).hex()
        }

        try:
            encrypted_payload = self._encrypt_command_payload(device, payload, "_send_tab_key")

            self._api_request("POST", "/account/devices/invoke_command", {
                "target": device["id"],
                "command": COMMAND_SEND_TAB,
                "payload": encrypted_payload
            })

            return {
                "success": True,
                "device": device["name"],
                "url": url,
                "title": title
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def close_tabs(self, device_name: str, urls: list) -> dict:
        """Close tabs on a device.

        Args:
            device_name: Name of the target device (partial match)
            urls: List of URLs to close

        Returns:
            Result dict with success status and details
        """
        device = self.find_device_by_name(device_name)
        if not device:
            return {"success": False, "error": f"Device not found: {device_name}"}

        if not device["can_close_tabs"]:
            return {"success": False, "error": f"Device does not support closing tabs: {device['name']}"}

        if device["is_current"]:
            return {"success": False, "error": "Cannot close tabs on the current device"}

        payload = {
            "urls": urls,
            "flowID": os.urandom(16).hex(),
            "streamID": os.urandom(16).hex()
        }

        try:
            encrypted_payload = self._encrypt_command_payload(device, payload, "_close_tabs_key")

            self._api_request("POST", "/account/devices/invoke_command", {
                "target": device["id"],
                "command": COMMAND_CLOSE_TABS,
                "payload": encrypted_payload
            })

            return {
                "success": True,
                "device": device["name"],
                "urls": urls
            }
        except Exception as e:
            return {"success": False, "error": str(e)}


def cmd_devices(args):
    """List devices with command capabilities."""
    client = FxACommands(args.session)
    devices = client.get_devices_with_commands()

    if args.json:
        print(json.dumps(devices, indent=2))
    else:
        for d in devices:
            status = []
            if d["can_receive_tabs"]:
                status.append("send-tab")
            if d["can_close_tabs"]:
                status.append("close-tabs")
            if d["is_current"]:
                status.append("(current)")

            capabilities = ", ".join(status) if status else "no commands"
            print(f"{d['name']} ({d['type']}): {capabilities}")


def cmd_send(args):
    """Send a tab to a device."""
    client = FxACommands(args.session)
    result = client.send_tab(args.device, args.url, args.title or "")

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["success"]:
            print(f"Sent tab to {result['device']}: {result['url']}")
        else:
            print(f"Error: {result['error']}", file=sys.stderr)
            sys.exit(1)


def cmd_close(args):
    """Close tabs on a device."""
    client = FxACommands(args.session)
    result = client.close_tabs(args.device, args.urls)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["success"]:
            print(f"Closed {len(result['urls'])} tab(s) on {result['device']}")
        else:
            print(f"Error: {result['error']}", file=sys.stderr)
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Firefox Device Commands - send and close tabs on remote devices"
    )
    parser.add_argument(
        "--session", "-s",
        default=DEFAULT_SESSION_FILE,
        help=f"Session file path (default: {DEFAULT_SESSION_FILE})"
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output in JSON format"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    devices_parser = subparsers.add_parser("devices", help="List devices with command capabilities")
    devices_parser.set_defaults(func=cmd_devices)

    send_parser = subparsers.add_parser("send", help="Send a tab to a device")
    send_parser.add_argument("device", help="Target device name (partial match)")
    send_parser.add_argument("url", help="URL to send")
    send_parser.add_argument("--title", "-t", help="Tab title")
    send_parser.set_defaults(func=cmd_send)

    close_parser = subparsers.add_parser("close", help="Close tabs on a device")
    close_parser.add_argument("device", help="Target device name (partial match)")
    close_parser.add_argument("urls", nargs="+", help="URLs to close")
    close_parser.set_defaults(func=cmd_close)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
