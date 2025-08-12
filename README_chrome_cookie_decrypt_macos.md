## macOS Chrome Cookie Decryptor (Python)

Advanced script and GUI to decrypt macOS Google Chrome/Chromium cookies using the profile's Cookies DB and the system Local State file.

### Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### CLI Usage

- Ensure Chrome is closed to avoid DB locks
- Defaults to Chrome `Default` profile

```bash
python3 chrome_cookie_decrypt_macos.py \
  --browser chrome \
  --profile "Default" \
  --domain example.com \
  --json
```

Options:
- `--browser`: `chrome` | `chrome-canary` | `chromium`
- `--profile`: e.g. `Default`, `Profile 1`
- `--local-state`: custom Local State path
- `--cookies`: custom Cookies DB path
- `--domain`: filter by domain substring
- `--name`: filter by cookie name substring
- `--json`: output JSON (otherwise TSV lines)
- `--output`: write to a file
- `--keychain-service`: override Keychain service name (default tries "Chrome Safe Storage" and "Chromium Safe Storage")
- `--keychain-account`: override Keychain account (default tries "Chrome" and "Chromium")

### GUI Usage

Run the GUI:

```bash
python3 chrome_cookie_decrypt_macos_gui.py
```

Features:
- Select `Local State` and `Cookies` files manually via file pickers
- Choose browser (`chrome`, `chrome-canary`, `chromium`) and profile name
- Filters: domain substring, cookie name substring
- Advanced options: override Keychain service/account
- Output formats: JSON or TSV; export to file
- Table view with host, name, value, path, expiry, flags; copy selected value to clipboard
- Options to include expired cookies and to show only AES-GCM (`v10`/`v11`) items

### How it works
- Derives the legacy AES-CBC key from macOS Keychain (PBKDF2-HMAC-SHA1, salt=`saltysalt`, iterations=1003)
- Reads `Local State` to get `os_crypt.encrypted_key`
- Decrypts master key (Chrome 80+) using AES-GCM with the legacy key
- Decrypts cookie values:
  - `v10`/`v11`: AES-GCM with master key
  - otherwise: legacy AES-CBC with IV=16 spaces

### Notes
- This tool is intended for macOS (`sys.platform == 'darwin'`).
- Close Chrome before running to avoid DB locks.
- Accessing Keychain may prompt for authentication or require the login keychain to be unlocked.
- Use responsibly and only on systems you own or have permission to access.