#!/usr/bin/env python3

import json
import sys
from pathlib import Path
from typing import List, Optional, Dict

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Import core logic from the CLI module
import chrome_cookie_decrypt_macos as core


class CookieDecryptGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("macOS Chrome Cookie Decryptor")
        self.geometry("980x640")
        self.minsize(880, 560)

        if sys.platform != "darwin":
            messagebox.showwarning(
                "Platform Warning",
                "This tool is designed for macOS and may not work on other platforms.",
            )

        # Variables
        self.browser_var = tk.StringVar(value="chrome")
        self.profile_var = tk.StringVar(value="Default")
        self.local_state_path_var = tk.StringVar(value="")
        self.cookies_path_var = tk.StringVar(value="")
        self.domain_filter_var = tk.StringVar(value="")
        self.name_filter_var = tk.StringVar(value="")
        self.output_format_var = tk.StringVar(value="json")  # json | tsv
        self.only_gcm_var = tk.BooleanVar(value=False)
        self.include_expired_var = tk.BooleanVar(value=False)
        self.kc_service_var = tk.StringVar(value="")
        self.kc_account_var = tk.StringVar(value="")

        self.status_var = tk.StringVar(value="Idle")

        self._build_ui()

    def _build_ui(self) -> None:
        root = self

        # Top controls frame
        top = ttk.Frame(root, padding=(8, 8, 8, 4))
        top.pack(fill=tk.X)

        # Browser and profile
        ttk.Label(top, text="Browser:").grid(row=0, column=0, sticky=tk.W, padx=(0, 6))
        browser_cb = ttk.Combobox(
            top, textvariable=self.browser_var, width=16, values=["chrome", "chrome-canary", "chromium"], state="readonly"
        )
        browser_cb.grid(row=0, column=1, sticky=tk.W, padx=(0, 16))

        ttk.Label(top, text="Profile:").grid(row=0, column=2, sticky=tk.W, padx=(0, 6))
        ttk.Entry(top, textvariable=self.profile_var, width=20).grid(row=0, column=3, sticky=tk.W, padx=(0, 16))

        # Local State file
        ttk.Label(top, text="Local State:").grid(row=1, column=0, sticky=tk.W, pady=(8, 0))
        ttk.Entry(top, textvariable=self.local_state_path_var, width=60).grid(row=1, column=1, columnspan=2, sticky=tk.W+tk.E, pady=(8, 0))
        ttk.Button(top, text="Browse...", command=self._browse_local_state).grid(row=1, column=3, sticky=tk.W, pady=(8, 0))

        # Cookies db
        ttk.Label(top, text="Cookies DB:").grid(row=2, column=0, sticky=tk.W, pady=(8, 0))
        ttk.Entry(top, textvariable=self.cookies_path_var, width=60).grid(row=2, column=1, columnspan=2, sticky=tk.W+tk.E, pady=(8, 0))
        ttk.Button(top, text="Browse...", command=self._browse_cookies).grid(row=2, column=3, sticky=tk.W, pady=(8, 0))

        # Filters
        ttk.Label(top, text="Domain filter:").grid(row=3, column=0, sticky=tk.W, pady=(8, 0))
        ttk.Entry(top, textvariable=self.domain_filter_var, width=30).grid(row=3, column=1, sticky=tk.W, pady=(8, 0))
        ttk.Label(top, text="Name filter:").grid(row=3, column=2, sticky=tk.W, pady=(8, 0))
        ttk.Entry(top, textvariable=self.name_filter_var, width=20).grid(row=3, column=3, sticky=tk.W, pady=(8, 0))

        # Format
        fmt_frame = ttk.Frame(top)
        fmt_frame.grid(row=4, column=0, columnspan=4, sticky=tk.W, pady=(8, 0))
        ttk.Label(fmt_frame, text="Output format:").pack(side=tk.LEFT)
        ttk.Radiobutton(fmt_frame, text="JSON", variable=self.output_format_var, value="json").pack(side=tk.LEFT, padx=(8, 0))
        ttk.Radiobutton(fmt_frame, text="TSV", variable=self.output_format_var, value="tsv").pack(side=tk.LEFT, padx=(8, 0))
        ttk.Checkbutton(fmt_frame, text="Only AES-GCM (v10/v11)", variable=self.only_gcm_var).pack(side=tk.LEFT, padx=(16, 0))
        ttk.Checkbutton(fmt_frame, text="Include expired", variable=self.include_expired_var).pack(side=tk.LEFT, padx=(16, 0))

        # Advanced options (Keychain overrides)
        adv = ttk.LabelFrame(root, text="Advanced", padding=(8, 4))
        adv.pack(fill=tk.X, padx=8, pady=4)
        ttk.Label(adv, text="Keychain service:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(adv, textvariable=self.kc_service_var, width=32).grid(row=0, column=1, sticky=tk.W, padx=(6, 16))
        ttk.Label(adv, text="Keychain account:").grid(row=0, column=2, sticky=tk.W)
        ttk.Entry(adv, textvariable=self.kc_account_var, width=32).grid(row=0, column=3, sticky=tk.W, padx=(6, 16))

        # Action buttons
        btns = ttk.Frame(root, padding=(8, 4))
        btns.pack(fill=tk.X)
        ttk.Button(btns, text="Decrypt", command=self._on_decrypt).pack(side=tk.LEFT)
        ttk.Button(btns, text="Export...", command=self._on_export).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(btns, text="Copy Value", command=self._copy_selected_value).pack(side=tk.LEFT, padx=(8, 0))

        ttk.Label(btns, textvariable=self.status_var).pack(side=tk.RIGHT)

        # Results table
        columns = (
            "host",
            "name",
            "value",
            "path",
            "expires",
            "secure",
            "http_only",
            "creation",
            "last_access",
            "encrypted",
            "gcm",
        )
        tree_frame = ttk.Frame(root, padding=(8, 4))
        tree_frame.pack(fill=tk.BOTH, expand=True)
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
            width = 140 if col in {"value", "host"} else 90
            self.tree.column(col, width=width, anchor=tk.W, stretch=True)
        yscroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        xscroll = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscroll=yscroll.set, xscroll=xscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self._results: List[Dict[str, object]] = []

        # Fill default paths
        self._update_default_paths()
        browser_cb.bind("<<ComboboxSelected>>", lambda e: self._update_default_paths())
        self.profile_var.trace_add("write", lambda *_: self._update_default_paths())

    def _update_default_paths(self) -> None:
        try:
            paths = core.get_default_paths(self.browser_var.get(), self.profile_var.get())
            if not self.local_state_path_var.get():
                self.local_state_path_var.set(str(paths.local_state))
            if not self.cookies_path_var.get():
                self.cookies_path_var.set(str(paths.cookies_db))
        except Exception:
            pass

    def _browse_local_state(self) -> None:
        p = filedialog.askopenfilename(title="Select Local State file", filetypes=[("Local State", "Local State"), ("All Files", "*.*")])
        if p:
            self.local_state_path_var.set(p)

    def _browse_cookies(self) -> None:
        p = filedialog.askopenfilename(title="Select Cookies SQLite DB", filetypes=[("SQLite DB", "Cookies*"), ("All Files", "*.*")])
        if p:
            self.cookies_path_var.set(p)

    def _decrypt_cookies(self) -> List[Dict[str, object]]:
        self.status_var.set("Decrypting...")
        self.update_idletasks()

        local_state_path = Path(self.local_state_path_var.get()).expanduser()
        cookies_path = Path(self.cookies_path_var.get()).expanduser()

        if not local_state_path.exists():
            raise FileNotFoundError(f"Local State not found: {local_state_path}")
        if not cookies_path.exists():
            raise FileNotFoundError(f"Cookies DB not found: {cookies_path}")

        # Keychain
        service_candidates = []
        account_candidates = []
        if self.kc_service_var.get():
            service_candidates.append(self.kc_service_var.get())
        else:
            if self.browser_var.get().startswith("chrome"):
                service_candidates.append("Chrome Safe Storage")
            if self.browser_var.get() == "chromium":
                service_candidates.append("Chromium Safe Storage")
        if self.kc_account_var.get():
            account_candidates.append(self.kc_account_var.get())
        else:
            if self.browser_var.get().startswith("chrome"):
                account_candidates.append("Chrome")
            if self.browser_var.get() == "chromium":
                account_candidates.append("Chromium")

        password = core.get_keychain_password(service_candidates, account_candidates)
        if not password:
            raise RuntimeError("Failed to retrieve Keychain password. Ensure your login keychain is unlocked.")

        legacy_key = core.derive_legacy_key_from_password(password)

        enc_master_key_raw = core.read_local_state_encrypted_key(local_state_path)
        master_key: Optional[bytes] = None
        if enc_master_key_raw and not enc_master_key_raw.startswith(b"DPAPI"):
            master_key = core.try_decrypt_master_key_with_legacy_key(enc_master_key_raw, legacy_key)

        db_copy = core.copy_sqlite_db(cookies_path)
        rows = core.fetch_cookies(db_copy)

        # Apply filters
        rows = core.filter_cookies(rows, self.domain_filter_var.get().strip() or None, self.name_filter_var.get().strip() or None)

        out = []
        for row in rows:
            expires = core.chrome_time_to_unix_epoch(int(row.get("expires_utc") or 0))
            if not self.include_expired_var.get() and expires and expires < 0:
                continue
            encrypted_value: bytes = row.get("encrypted_value") or b""
            raw_value: str = row.get("value") or ""

            dec: Optional[str] = None
            if encrypted_value:
                if self.only_gcm_var.get() and not encrypted_value.startswith(core.V_PREFIXES):
                    continue
                dec = core.decrypt_cookie_value(encrypted_value, master_key, legacy_key)
            if not dec and raw_value:
                dec = raw_value

            out.append({
                "host": row.get("host_key"),
                "name": row.get("name"),
                "value": dec or "",
                "path": row.get("path"),
                "expires": expires,
                "secure": bool(row.get("is_secure")),
                "http_only": bool(row.get("is_httponly")),
                "creation": core.chrome_time_to_unix_epoch(int(row.get("creation_utc") or 0)),
                "last_access": core.chrome_time_to_unix_epoch(int(row.get("last_access_utc") or 0)),
                "encrypted": bool(encrypted_value),
                "gcm": bool(encrypted_value and encrypted_value.startswith(core.V_PREFIXES)),
            })

        self.status_var.set(f"Decrypted {len(out)} cookies")
        return out

    def _on_decrypt(self) -> None:
        try:
            self._results = self._decrypt_cookies()
            self._populate_tree(self._results)
        except Exception as exc:
            messagebox.showerror("Decryption failed", str(exc))
            self.status_var.set("Failed")

    def _populate_tree(self, rows: List[Dict[str, object]]) -> None:
        self.tree.delete(*self.tree.get_children())
        for r in rows:
            self.tree.insert("", tk.END, values=(
                r.get("host"),
                r.get("name"),
                r.get("value"),
                r.get("path"),
                r.get("expires"),
                str(r.get("secure")),
                str(r.get("http_only")),
                r.get("creation"),
                r.get("last_access"),
                str(r.get("encrypted")),
                str(r.get("gcm")),
            ))

    def _on_export(self) -> None:
        if not self._results:
            messagebox.showinfo("Nothing to export", "Please decrypt cookies first.")
            return
        fp = filedialog.asksaveasfilename(
            title="Save cookies",
            defaultextension=(".json" if self.output_format_var.get() == "json" else ".tsv"),
            filetypes=[
                ("JSON", "*.json"),
                ("TSV", "*.tsv"),
                ("All Files", "*.*"),
            ],
        )
        if not fp:
            return

        try:
            if self.output_format_var.get() == "json":
                text = json.dumps(self._results, ensure_ascii=False, indent=2)
            else:
                lines = []
                for c in self._results:
                    lines.append(
                        f"{c['host']}\t{c['name']}={c['value']}\tpath={c['path']}\tsecure={c['secure']}\thttp_only={c['http_only']}\texpires={c['expires']}"
                    )
                text = "\n".join(lines)
            Path(fp).write_text(text, encoding="utf-8")
            messagebox.showinfo("Export complete", f"Wrote {len(self._results)} cookies to {fp}")
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))

    def _copy_selected_value(self) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        item = self.tree.item(selection[0])
        # Columns: host, name, value, ...
        values = item.get("values", [])
        if len(values) >= 3:
            val = values[2]
            self.clipboard_clear()
            self.clipboard_append(val)
            self.status_var.set("Copied value to clipboard")


if __name__ == "__main__":
    app = CookieDecryptGUI()
    app.mainloop()