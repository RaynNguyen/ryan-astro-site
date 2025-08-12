## macOS Chrome Cookie Decryptor (Basic)

Minimal script to decrypt macOS Google Chrome/Chromium cookies using user-provided `Local State` and `Cookies` files.

### Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Usage

- Close Chrome to avoid DB locks.
- Provide explicit paths to your `Local State` and `Cookies` files.

```bash
python3 chrome_cookie_decrypt_basic.py \
  --local-state "/Users/you/Library/Application Support/Google/Chrome/Local State" \
  --cookies "/Users/you/Library/Application Support/Google/Chrome/Default/Cookies" \
  --domain example.com \
  --json
```

Options:
- `--local-state`: path to the `Local State` file
- `--cookies`: path to the `Cookies` SQLite DB
- `--domain`: filter by domain substring (optional)
- `--name`: filter by cookie name substring (optional)
- `--json`: output JSON (default is TSV lines)

### Notes
- macOS only (`sys.platform == 'darwin'`).
- Retrieves the Keychain secret and derives the legacy key.
- Decrypts Chrome 80+ AES-GCM (`v10`/`v11`) cookies with the master key from `Local State`; falls back to legacy AES-CBC for older entries.
- Use responsibly on systems you own or have permission to access.