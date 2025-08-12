#!/usr/bin/env python3

import argparse
import json
from pathlib import Path
from typing import List, Dict, Optional

import sys

# Reuse decryption logic from the core module
import chrome_cookie_decrypt_macos as core


def main() -> None:
    if sys.platform != "darwin":
        print("Warning: This script targets macOS and may not work elsewhere.", file=sys.stderr)

    parser = argparse.ArgumentParser(description="Basic macOS Chrome cookie decryptor using explicit file paths.")
    parser.add_argument("--local-state", required=True, help="Path to the 'Local State' file")
    parser.add_argument("--cookies", required=True, help="Path to the 'Cookies' SQLite DB")
    parser.add_argument("--domain", default=None, help="Filter by domain substring")
    parser.add_argument("--name", default=None, help="Filter by cookie name substring")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of TSV")

    args = parser.parse_args()

    local_state = Path(args.local_state).expanduser()
    cookies_db = Path(args.cookies).expanduser()

    if not local_state.exists():
        raise SystemExit(f"Local State not found: {local_state}")
    if not cookies_db.exists():
        raise SystemExit(f"Cookies DB not found: {cookies_db}")

    # Try common Keychain credentials
    service_candidates = ["Chrome Safe Storage", "Chromium Safe Storage"]
    account_candidates = ["Chrome", "Chromium"]

    password = core.get_keychain_password(service_candidates, account_candidates)
    if not password:
        raise SystemExit("Failed to retrieve Keychain password. Ensure the login keychain is unlocked.")

    legacy_key = core.derive_legacy_key_from_password(password)

    enc_master_key_raw = core.read_local_state_encrypted_key(local_state)
    master_key: Optional[bytes] = None
    if enc_master_key_raw and not enc_master_key_raw.startswith(b"DPAPI"):
        master_key = core.try_decrypt_master_key_with_legacy_key(enc_master_key_raw, legacy_key)

    db_copy = core.copy_sqlite_db(cookies_db)
    rows: List[Dict[str, object]] = core.fetch_cookies(db_copy)
    rows = core.filter_cookies(rows, args.domain, args.name)

    out: List[Dict[str, object]] = []
    for row in rows:
        encrypted_value: bytes = row.get("encrypted_value") or b""
        raw_value: str = row.get("value") or ""

        dec: Optional[str] = None
        if encrypted_value:
            dec = core.decrypt_cookie_value(encrypted_value, master_key, legacy_key)
        if not dec and raw_value:
            dec = raw_value

        out.append({
            "host": row.get("host_key"),
            "name": row.get("name"),
            "value": dec or "",
            "path": row.get("path"),
            "expires": core.chrome_time_to_unix_epoch(int(row.get("expires_utc") or 0)),
            "secure": bool(row.get("is_secure")),
            "http_only": bool(row.get("is_httponly")),
        })

    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        for c in out:
            print(f"{c['host']}\t{c['name']}={c['value']}\tpath={c['path']}\tsecure={c['secure']}\thttp_only={c['http_only']}\texpires={c['expires']}")


if __name__ == "__main__":
    main()