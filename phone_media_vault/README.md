# Phone Media Vault — user & developer guide

**Version 1.0.0 — all stages implemented:** ADB + scanner, verified backup
engine + Ed25519 signing, integrity verifier, restore, safe wipe, encrypted
export, WebView GUI, CLI, installer.

## Requirements

- Python 3.10 or newer (Windows 10/11 is the primary target; Linux/macOS work
  with a password-protected signing key).
- Android Platform-Tools (`adb`). The app checks its own `platform-tools`
  folder first, then the system `PATH`.
- A phone connected over USB with **USB debugging** enabled and its RSA prompt
  accepted.
- Python packages:

  ```powershell
  python -m pip install -r phone_media_vault/requirements.txt
  ```

  `cryptography` is required. `pywebview` gives the native window (without it
  the app opens in your browser). `pyzipper` is only needed for encrypted
  export.

## Running the app

From the `phone_media_vault` folder:

```powershell
python main.py                 # native window (Edge WebView2)
python main.py --browser       # UI in the default browser (http://127.0.0.1:8765)
python main.py --demo          # simulated phone + temporary key/settings
python main.py --debug         # WebView developer tools
```

From the repository root, `python -m phone_media_vault` does the same.

### Typical workflow

1. **الجهاز (Device)** — the connected phone is detected; select it.
2. **النسخ الاحتياطي (Backup)** — tick folders (or add a custom shared-storage
   folder), press *فحص الملفات* to see counts/sizes, choose a destination, and
   start. Use the **same destination folder for the same phone every time**:
   the backup is incremental, already-verified files are skipped after a fresh
   phone hash check, and nothing is ever overwritten. Pause/resume/cancel at any
   time; a cancelled or disconnected backup resumes from the same folder.
3. **التحقق (Verify)** — re-checks the signature and every file offline and
   writes `verification_report.html` in the backup folder.
4. **الاستعادة (Restore)** — writes files back to the phone (to a separate
   folder such as `/sdcard/Restored`, or to the original paths).
5. **تحرير المساحة (Safe wipe)** — first shows exactly which files can be
   deleted and why the rest are kept, then deletes only after you type the
   confirmation phrase.
6. **تصدير مشفّر (Encrypted export)** — AES-256 ZIP for off-site storage.

### Signing key

On first use, Windows protects the Ed25519 private key with current-user
DPAPI automatically. Where DPAPI is unavailable, the UI asks for a password
(8+ characters) and stores the key password-encrypted; there is never a
plaintext fallback. The key and the local public-key trust anchor live under
`%LOCALAPPDATA%\PhoneMediaVault\keys` and never inside a backup. Each backup
contains `manifest.json`, `manifest.sig`, `public_key.pem`, `backup_log.txt`,
and the `files/` tree (`files/internal/…`, `files/sdcard-xxxx-xxxx/…`).

## Safety guarantees

**Scanning and backup never write to the phone.** `Android/data`,
`Android/obb`, and WhatsApp `Databases`/`Backups` are pruned on-device and are
also refused as write/delete targets. Phone paths are validated and quoted
with `shlex.quote`; local ADB calls use argv lists (no local shell).

**Backup:** every pull lands in a unique `.part` file and is installed only
when its local SHA-256 matches the phone's (or two independent pulls agree
when the phone lacks `sha256sum`). Existing untracked files are adopted only if
they match the live phone. Scan warnings prevent a backup from being marked
fully verified.

**Restore:** requires a valid (and locally trusted) signature; re-hashes each
local copy before pushing; pushes to a temporary name, verifies on the phone,
then moves with `mv -n`. Existing phone files are never replaced — identical
files are reported as already present, different ones are skipped or restored
as `name (restored N).ext`.

**Safe wipe** deletes a phone file only when all of the following hold:

1. the manifest signature is valid and signed by this computer's key;
2. the backup belongs to the connected phone (serial or hashed serial);
3. the entry is `verified` and the local copy matches its size and SHA-256 now;
4. the phone file still has the recorded size and mtime **and** the phone's
   own SHA-256 matches (phones without `sha256sum` are never wiped);
5. you typed the confirmation phrase, and the plan is less than 30 minutes old.

Each file is re-checked immediately before deletion; only single regular files
are removed (no recursion). Every action is appended to `wipe_log.txt`.

## Command-line interface

```powershell
python -m phone_media_vault.cli devices
python -m phone_media_vault.cli sources
python -m phone_media_vault.cli scan   --source folder:dcim
python -m phone_media_vault.cli backup --source folder:dcim --source folder:whatsapp-legacy --destination D:\Vault\MyPhone
python -m phone_media_vault.cli verify D:\Vault\MyPhone --report D:\Vault\report.html
python -m phone_media_vault.cli restore D:\Vault\MyPhone --target /sdcard/Restored
python -m phone_media_vault.cli wipe D:\Vault\MyPhone --dry-run
python -m phone_media_vault.cli export D:\Vault\MyPhone E:\MyPhone.zip
```

Global options: `--serial`, `--adb PATH`, `--demo`. The signing-key password
can be supplied via `PMV_KEY_PASSWORD`, the archive password via
`PMV_ARCHIVE_PASSWORD`. Exit code 0 = success, 2 = finished with problems.

The original diagnostic smoke test (max. 10 files, real device) is still
available: `python tools\smoke_backup.py /sdcard/DCIM/Camera --destination D:\PMV-Smoke\run-01`.

## Building the Windows app and installer

```powershell
powershell -ExecutionPolicy Bypass -File phone_media_vault\installer\build.ps1 -DownloadAdb
```

This installs `requirements-dev.txt`, runs the tests, optionally downloads
Android Platform-Tools into `platform-tools/` (bundled with the app), builds
`phone_media_vault\dist\PhoneMediaVault\PhoneMediaVault.exe` with PyInstaller,
and — if Inno Setup 6 is installed — creates
`phone_media_vault\dist\installer\PhoneMediaVault-Setup-<version>.exe`.
Put an `app.ico` in `installer/assets/` to brand the executable and installer.
The installer requires no admin rights and keeps user data on uninstall so
existing backups stay verifiable.

## Project layout

```
phone_media_vault/
  main.py, __main__.py, cli.py      entry points
  core/   adb_manager.py            read-only ADB access
          adb_writer.py             phone writes (restore/wipe only)
          scanner.py, models.py     discovery + read-only scan
          backup_engine.py          verified incremental backup
          signer.py                 Ed25519 + DPAPI/password key storage
          verifier.py               offline integrity verification
          restore.py, wipe.py       restore and safe wipe
          report.py, archive.py     HTML reports, AES ZIP export
          settings.py               settings + history (app data)
  app/    api.py, jobs.py           GUI bridge + background jobs
          desktop.py, server.py     pywebview window / browser mode
          demo.py                   simulated phone
  ui/     index.html, css/, js/     Arabic RTL interface
  installer/                        PyInstaller spec, Inno Setup, build.ps1
  tests/                            unit + end-to-end tests
```

## Run tests

From the repository root:

```powershell
python -m unittest discover -s phone_media_vault/tests -v
```

The suite uses the simulated phone for end-to-end backup → verify → restore →
wipe → export flows; no device is needed. CI runs it on Windows and Ubuntu.
