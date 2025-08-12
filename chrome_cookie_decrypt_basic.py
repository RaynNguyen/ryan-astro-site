#!/usr/bin/env python3

import argparse
import base64
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding as sym_padding


# Constants for legacy Chrome encryption on macOS
SALTY_SALT = b"saltysalt"
PBKDF2_ITERATIONS = 1003
DERIVED_KEY_LEN = 16  # 128-bit key
LEGACY_IV = b" " * 16  # 16 spaces for AES-CBC IV
V_PREFIXES = (b"v10", b"v11")


def get_keychain_password(service_names: Iterable[str], account_names: Iterable[str]) -> Optional[bytes]:
    """Retrieve the Chrome/Chromium Keychain password using the macOS `security` CLI."""
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
    """PBKDF2-HMAC-SHA1 to derive the legacy AES key used by Chrome on macOS."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=DERIVED_KEY_LEN,
        salt=SALTY_SALT,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password)


def read_local_state_encrypted_key(local_state_path: Path) -> Optional[bytes]:
    data = json.loads(local_state_path.read_text(encoding="utf-8"))
    key_b64 = data.get("os_crypt", {}).get("encrypted_key")
    if not key_b64:
        return None
    return base64.b64decode(key_b64)


def pkcs7_unpad(data: bytes) -> bytes:
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def decrypt_aes_cbc_pkcs7(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(padded)


def try_decrypt_master_key_with_legacy_key(encrypted_key_raw: bytes, legacy_key: bytes) -> Optional[bytes]:
    """Decrypt the Chrome 80+ master key from Local State using the legacy key (macOS)."""
    try:
        if encrypted_key_raw.startswith(b"DPAPI"):
            # Windows-only; not applicable on macOS
            return None
        if encrypted_key_raw.startswith(V_PREFIXES):
            nonce = encrypted_key_raw[3:15]
            cipher_and_tag = encrypted_key_raw[15:]
            return AESGCM(legacy_key).decrypt(nonce, cipher_and_tag, None)
        # Rare fallback: older CBC wrapping
        try:
            return decrypt_aes_cbc_pkcs7(encrypted_key_raw, legacy_key, LEGACY_IV)
        except Exception:
            return None
    except Exception:
        return None


def decrypt_cookie_value(encrypted_value: bytes, master_key: Optional[bytes], legacy_key: Optional[bytes]) -> Optional[str]:
    if not encrypted_value:
        return None
    try:
        if encrypted_value.startswith(V_PREFIXES):
            if not master_key:
                return None
            nonce = encrypted_value[3:15]
            cipher_and_tag = encrypted_value[15:]
            pt = AESGCM(master_key).decrypt(nonce, cipher_and_tag, None)
            return pt.decode("utf-8", errors="replace")
        if legacy_key:
            pt = decrypt_aes_cbc_pkcs7(encrypted_value, legacy_key, LEGACY_IV)
            return pt.decode("utf-8", errors="replace")
        return encrypted_value.decode("utf-8", errors="replace")
    except Exception:
        return None


def copy_sqlite_db(src: Path) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="chrome_cookies_"))
    dst = tmp / "Cookies"
    shutil.copy2(src, dst)
    return dst


def chrome_time_to_unix_epoch(chrome_time: int) -> int:
    if not chrome_time:
        return 0
    return int(chrome_time / 1_000_000 - 11644473600)


def fetch_cookies(db_path: Path) -> List[Dict[str, object]]:
    query = (
        "SELECT host_key, name, path, expires_utc, is_secure, is_httponly, creation_utc, last_access_utc, encrypted_value, value FROM cookies"
    )
    results: List[Dict[str, object]] = []
    conn = sqlite3.connect(str(db_path))
    try:
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
        conn.close()
    return results


def filter_cookies(cookies: List[Dict[str, object]], domain: Optional[str], name: Optional[str]) -> List[Dict[str, object]]:
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
    if sys.platform != "darwin":
        print("Warning: This script targets macOS and may not work elsewhere.", file=sys.stderr)

    p = argparse.ArgumentParser(
        description="Decrypt Chrome/Chromium cookies on macOS using explicit Local State and Cookies paths."
    )
    p.add_argument("--local-state", required=True, help="Path to the 'Local State' file")
    p.add_argument("--cookies", required=True, help="Path to the 'Cookies' SQLite DB")
    p.add_argument("--domain", default=None, help="Filter by domain substring")
    p.add_argument("--name", default=None, help="Filter by cookie name substring")
    p.add_argument("--json", action="store_true", help="Output JSON instead of TSV")
    args = p.parse_args()

    local_state = Path(args.local_state).expanduser()
    cookies_db = Path(args.cookies).expanduser()

    if not local_state.exists():
        raise SystemExit(f"Local State not found: {local_state}")
    if not cookies_db.exists():
        raise SystemExit(f"Cookies DB not found: {cookies_db}")

    # Retrieve Keychain secret and derive legacy key
    password = get_keychain_password(["Chrome Safe Storage", "Chromium Safe Storage"], ["Chrome", "Chromium"])
    if not password:
        raise SystemExit("Failed to retrieve Keychain password. Ensure the login keychain is unlocked.")
    legacy_key = derive_legacy_key_from_password(password)

    # Decrypt master key for AES-GCM cookies (Chrome 80+)
    enc_master_key_raw = read_local_state_encrypted_key(local_state)
    master_key: Optional[bytes] = None
    if enc_master_key_raw and not enc_master_key_raw.startswith(b"DPAPI"):
        master_key = try_decrypt_master_key_with_legacy_key(enc_master_key_raw, legacy_key)

    # Work on a copy of the DB to avoid locks
    db_copy = copy_sqlite_db(cookies_db)

    rows = fetch_cookies(db_copy)
    rows = filter_cookies(rows, args.domain, args.name)

    out: List[Dict[str, object]] = []
    for row in rows:
        encrypted_value: bytes = row.get("encrypted_value") or b""
        raw_value: str = row.get("value") or ""

        dec: Optional[str] = None
        if encrypted_value:
            dec = decrypt_cookie_value(encrypted_value, master_key, legacy_key)
        if not dec and raw_value:
            dec = raw_value

        out.append({
            "host": row.get("host_key"),
            "name": row.get("name"),
            "value": dec or "",
            "path": row.get("path"),
            "expires": chrome_time_to_unix_epoch(int(row.get("expires_utc") or 0)),
            "secure": bool(row.get("is_secure")),
            "http_only": bool(row.get("is_httponly")),
        })

    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        for c in out:
            print(
                f"{c['host']}\t{c['name']}={c['value']}\tpath={c['path']}\tsecure={c['secure']}\thttp_only={c['http_only']}\texpires={c['expires']}"
            )


if __name__ == "__main__":
    main()