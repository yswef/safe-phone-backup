# Phone Media Vault (خزنة الوسائط)

Verified, incremental Android-media backup for Windows — with an Arabic RTL
desktop interface, signed manifests, offline integrity verification, safe
restore, and a "free up phone space" mode that only deletes files that are
proven to be safely backed up.

## Features

| Area | What it does |
| --- | --- |
| **Device** | ADB discovery, explicit device selection, clear Arabic messages for unauthorized/offline phones. |
| **Scan** | Read-only scan of DCIM, Pictures, Movies, WhatsApp/Telegram media, Downloads, full internal storage, SD cards, or custom folders. `Android/data`, `Android/obb`, and WhatsApp `Databases`/`Backups` are always excluded; symlinks are never followed. |
| **Backup** | Phone-side SHA-256 → pull to `.part` → local SHA-256 → install only on match (double-pull fallback). Incremental/resumable, never overwrites, pause/resume/cancel, retries, speed + ETA. |
| **Signing** | Deterministic `manifest.json` signed with Ed25519; private key kept in per-user app data (Windows DPAPI or password-encrypted, never plaintext). |
| **Verify** | Offline check of the signature, key trust, and every file's size + SHA-256; detects missing, modified, extra, and leftover `.part` files. Arabic HTML report. |
| **Restore** | Back to original paths or to a separate phone folder. Re-verifies each local file first, pushes to a temp name, verifies on the phone, then `mv -n`. Never overwrites (skip or rename on conflict). |
| **Safe wipe** | Deletes phone files only if the signature is valid, the backup is from *this* phone, the local copy matches its hash, and the live phone file is unchanged with a matching phone-side SHA-256. Requires a typed confirmation phrase; re-checks every file right before deleting; full audit log. |
| **Encrypted export** | AES-256 ZIP (7-Zip/WinRAR compatible), every member re-verified after writing. |
| **History & settings** | Default destination, retries, auto-verify, serial hashing, restore defaults. |
| **Interfaces** | Native window (pywebview / WebView2), browser mode, full CLI, and a demo mode with a simulated phone. |
| **Packaging** | PyInstaller spec, Inno Setup installer script, one-command PowerShell build, GitHub Actions CI. |

## Quick start (Windows)

```powershell
python -m pip install -r phone_media_vault\requirements.txt
cd phone_media_vault
python main.py            # native window
python main.py --demo     # try it without a phone
```

See [`phone_media_vault/README.md`](phone_media_vault/README.md) for the full
guide: requirements, every mode, the CLI, safety guarantees, building the
installer, and running tests.
