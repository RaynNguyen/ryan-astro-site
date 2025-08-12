#!/usr/bin/env python3

import argparse
import base64
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding as sym_padding


SALTY_SALT = b"saltysalt"
PBKDF2_ITERATIONS = 1003
DERIVED_KEY_LEN = 16  # 128-bit legacy key
LEGACY_IV = b" " * 16  # 16 spaces for AES-CBC IV
V_PREFIXES = (b"v10", b"v11")


@dataclass
class ChromePaths:
    local_state: Path
    cookies_db: Path


def _is_macos() -> bool:
    return sys.platform == "darwin"


def _fail(msg: str) -> None:
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(1)


def get_default_paths(browser: str, profile: str) -> ChromePaths:
    home = Path.home()
    # Common base dirs for macOS
    if browser.lower() == "chrome":
        base = home / "Library" / "Application Support" / "Google" / "Chrome"
    elif browser.lower() == "chrome-canary":
        base = home / "Library" / "Application Support" / "Google" / "Chrome Canary"
    elif browser.lower() == "chromium":
        base = home / "Library" / "Application Support" / "Chromium"
    else:
        _fail(f"Unsupported browser '{browser}'. Use chrome, chrome-canary, or chromium.")

    return ChromePaths(
        local_state=base / "Local State",
        cookies_db=base / profile / "Cookies",
    )


def read_local_state_encrypted_key(local_state_path: Path) -> Optional[bytes]:
    if not local_state_path.exists():
        _fail(f"Local State not found at: {local_state_path}")
    try:
        with local_state_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        key_b64 = data.get("os_crypt", {}).get("encrypted_key")
        if not key_b64:
            return None
        key_raw = base64.b64decode(key_b64)
        return key_raw
    except Exception as exc:
        _fail(f"Failed to read Local State: {exc}")
    return None


def get_keychain_password(service_names: Iterable[str], account_names: Iterable[str]) -> Optional[bytes]:
    # Use macOS `security` CLI to extract the password from Keychain. Try combinations.
    for service in service_names:
        for account in account_names:
            try:
                out = subprocess.check_output(
                    [
                        "security",
                        "find-generic-password",
                        "-w",
                        "-s",
                        service,
                        "-a",
                        account,
                    ],
                    stderr=subprocess.DEVNULL,
                )
                if out:
                    return out.rstrip(b"\n")
            except subprocess.CalledProcessError:
                continue
    return None


def derive_legacy_key_from_password(password: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=DERIVED_KEY_LEN,
        salt=SALTY_SALT,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password)


def pkcs7_unpad(data: bytes) -> bytes:
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def decrypt_aes_cbc_pkcs7(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(padded)


def try_decrypt_master_key_with_legacy_key(encrypted_key_raw: bytes, legacy_key: bytes) -> Optional[bytes]:
    # On macOS/Linux the encrypted master key is typically formatted with 'v10'/'v11' prefix,
    # followed by 12-byte nonce, ciphertext and 16-byte tag (AES-GCM).
    try:
        if encrypted_key_raw.startswith(b"DPAPI"):
            # macOS should not present DPAPI; handled only on Windows.
            return None
        # Some platforms embed 'v10'/'v11' in encrypted_key. If so, decrypt via AES-GCM using the legacy key.
        if encrypted_key_raw.startswith(V_PREFIXES):
            nonce = encrypted_key_raw[3:15]
            cipher_and_tag = encrypted_key_raw[15:]
            aesgcm = AESGCM(legacy_key)
            return aesgcm.decrypt(nonce, cipher_and_tag, None)
        # Fallback: some older builds might store master key encrypted via AES-CBC with IV of spaces
        # using the legacy key. This is rare but we try for completeness.
        try:
            return decrypt_aes_cbc_pkcs7(encrypted_key_raw, legacy_key, LEGACY_IV)
        except Exception:
            return None
    except Exception:
        return None


def decrypt_cookie_value(
    encrypted_value: bytes,
    master_key: Optional[bytes],
    legacy_key: Optional[bytes],
) -> Optional[str]:
    if not encrypted_value:
        return None

    try:
        # Chrome 80+: AES-GCM cookie values have 'v10' / 'v11' prefix
        if encrypted_value.startswith(V_PREFIXES):
            if not master_key:
                return None
            nonce = encrypted_value[3:15]
            cipher_and_tag = encrypted_value[15:]
            plaintext = AESGCM(master_key).decrypt(nonce, cipher_and_tag, None)
            return plaintext.decode("utf-8", errors="replace")

        # Legacy: AES-CBC with IV of 16 spaces using legacy key
        if legacy_key:
            plaintext = decrypt_aes_cbc_pkcs7(encrypted_value, legacy_key, LEGACY_IV)
            return plaintext.decode("utf-8", errors="replace")

        # Not encrypted (older entries may store in 'value' column instead)
        try:
            return encrypted_value.decode("utf-8", errors="replace")
        except Exception:
            return None
    except Exception:
        return None


def copy_sqlite_db(src: Path) -> Path:
    if not src.exists():
        _fail(f"Cookies DB not found at: {src}")
    tmpdir = Path(tempfile.mkdtemp(prefix="chrome_cookies_"))
    dst = tmpdir / "Cookies"
    try:
        shutil.copy2(src, dst)
    except Exception as exc:
        _fail(f"Failed to copy cookies DB: {exc}")
    return dst


def chrome_time_to_unix_epoch(chrome_time: int) -> int:
    # Chrome/WebKit epoch starts at 1601-01-01, microseconds
    # Convert to Unix epoch seconds
    if not chrome_time:
        return 0
    return int(chrome_time / 1_000_000 - 11644473600)


def fetch_cookies(db_path: Path) -> List[Dict[str, object]]:
    query = (
        "SELECT host_key, name, path, expires_utc, is_secure, is_httponly, "
        "creation_utc, last_access_utc, encrypted_value, value FROM cookies"
    )
    results: List[Dict[str, object]] = []
    conn = None

    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(query)
        for row in cur.fetchall():
            results.append({
                "host_key": row["host_key"],
                "name": row["name"],
                "path": row["path"],
                "expires_utc": row["expires_utc"],
                "is_secure": row["is_secure"],
                "is_httponly": row["is_httponly"],
                "creation_utc": row["creation_utc"],
                "last_access_utc": row["last_access_utc"],
                "encrypted_value": row["encrypted_value"],
                "value": row["value"],
            })
    finally:
        if conn is not None:
            conn.close()
    return results


def filter_cookies(
    cookies: List[Dict[str, object]],
    domain: Optional[str],
    name: Optional[str],
) -> List[Dict[str, object]]:
    def match(val: str, needle: Optional[str]) -> bool:
        if not needle:
            return True
        return needle.lower() in (val or "").lower()

    out: List[Dict[str, object]] = []
    for c in cookies:
        if match(c.get("host_key", ""), domain) and match(c.get("name", ""), name):
            out.append(c)
    return out


def main() -> None:
    if not _is_macos():
        _fail("This script targets macOS. It may not work on other platforms.")

    parser = argparse.ArgumentParser(
        description=(
            "Decrypt macOS Google Chrome/Chromium cookies using Local State (Chrome 80+) "
            "and Keychain (legacy fallback)."
        )
    )
    parser.add_argument("--browser", default="chrome", choices=["chrome", "chrome-canary", "chromium"], help="Browser profile base to use")
    parser.add_argument("--profile", default="Default", help="Profile directory name, e.g., 'Default', 'Profile 1'")
    parser.add_argument("--local-state", dest="local_state", default=None, help="Path to Local State file (overrides default)")
    parser.add_argument("--cookies", dest="cookies", default=None, help="Path to Cookies sqlite DB (overrides default)")
    parser.add_argument("--domain", dest="domain", default=None, help="Filter by domain substring")
    parser.add_argument("--name", dest="name", default=None, help="Filter by cookie name substring")
    parser.add_argument("--json", dest="as_json", action="store_true", help="Output JSON")
    parser.add_argument("--output", dest="output", default=None, help="Write output to file path")
    parser.add_argument("--keychain-service", dest="kc_service", default=None, help="Override Keychain service name")
    parser.add_argument("--keychain-account", dest="kc_account", default=None, help="Override Keychain account name")

    args = parser.parse_args()

    paths = get_default_paths(args.browser, args.profile)
    local_state = Path(args.local_state) if args.local_state else paths.local_state
    cookies_db = Path(args.cookies) if args.cookies else paths.cookies_db

    # Resolve Keychain credentials
    service_candidates = [
        args.kc_service,
        "Chrome Safe Storage" if args.browser.startswith("chrome") else None,
        "Chromium Safe Storage" if args.browser == "chromium" else None,
    ]
    service_candidates = [s for s in service_candidates if s]
    if not service_candidates:
        service_candidates = ["Chrome Safe Storage", "Chromium Safe Storage"]

    account_candidates = [
        args.kc_account,
        "Chrome" if args.browser.startswith("chrome") else None,
        "Chromium" if args.browser == "chromium" else None,
    ]
    account_candidates = [a for a in account_candidates if a]
    if not account_candidates:
        account_candidates = ["Chrome", "Chromium"]

    password = get_keychain_password(service_candidates, account_candidates)
    if not password:
        _fail(
            "Failed to retrieve Keychain password. You may need to unlock the login keychain or adjust --keychain-* options."
        )

    legacy_key = derive_legacy_key_from_password(password)

    # Master key for AES-GCM (Chrome 80+)
    master_key: Optional[bytes] = None
    enc_master_key_raw = read_local_state_encrypted_key(local_state)
    if enc_master_key_raw:
        # On Windows, the key begins with b'DPAPI' and must be decrypted via DPAPI.
        # On macOS, we attempt AES-GCM with the legacy key or, as a fallback, AES-CBC.
        if enc_master_key_raw.startswith(b"DPAPI"):
            # Not expected on macOS, ignore
            master_key = None
        else:
            # Some platforms store the encrypted key again as base64-wrapped; unwrap if needed
            # Often it's already raw v10 bytes at this point
            master_key = try_decrypt_master_key_with_legacy_key(enc_master_key_raw, legacy_key)

    # Copy the DB to avoid locks
    db_copy = copy_sqlite_db(cookies_db)

    cookies_rows = fetch_cookies(db_copy)
    cookies_rows = filter_cookies(cookies_rows, args.domain, args.name)

    output_rows: List[Dict[str, object]] = []

    for row in cookies_rows:
        encrypted_value: bytes = row.get("encrypted_value") or b""
        raw_value: str = row.get("value") or ""

        decrypted: Optional[str] = None
        if encrypted_value:
            decrypted = decrypt_cookie_value(encrypted_value, master_key, legacy_key)
        if not decrypted and raw_value:
            decrypted = raw_value

        output_rows.append({
            "host": row.get("host_key"),
            "name": row.get("name"),
            "path": row.get("path"),
            "value": decrypted or "",
            "expires": chrome_time_to_unix_epoch(int(row.get("expires_utc") or 0)),
            "secure": bool(row.get("is_secure")),
            "http_only": bool(row.get("is_httponly")),
            "creation": chrome_time_to_unix_epoch(int(row.get("creation_utc") or 0)),
            "last_access": chrome_time_to_unix_epoch(int(row.get("last_access_utc") or 0)),
            "encrypted": bool(encrypted_value),
            "gcm": bool(encrypted_value and encrypted_value.startswith(V_PREFIXES)),
        })

    # Output
    out_text: str
    if args.as_json:
        out_text = json.dumps(output_rows, ensure_ascii=False, indent=2)
    else:
        lines: List[str] = []
        for c in output_rows:
            lines.append(
                f"{c['host']}\t{c['name']}={c['value']}\tpath={c['path']}\tsecure={c['secure']}\thttp_only={c['http_only']}\texpires={c['expires']}"
            )
        out_text = "\n".join(lines)

    if args.output:
        Path(args.output).write_text(out_text, encoding="utf-8")
        print(f"Wrote {len(output_rows)} cookies to {args.output}")
    else:
        print(out_text)


if __name__ == "__main__":
    main()