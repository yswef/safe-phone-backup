# Phone Media Vault — development stages

**Current stage: 2 — verified backup engine and Ed25519 signing.**

Stage 1 provides ADB discovery and a read-only Android storage scanner. Stage 2
adds a verified phone-to-computer backup engine, deterministic manifest, and
protected signing-key storage. The integrity-verifier UI, restore, wipe, WebView
GUI, and installer are not implemented yet.

## Requirements

- Python 3.10 or newer.
- Android Platform-Tools (`adb`). The ADB manager checks the app's
  `platform-tools` directory first and then the system `PATH`.
- Install the current Python dependency from the repository root:

  ```powershell
  python -m pip install -r phone_media_vault/requirements.txt
  ```

- An Android phone connected over USB with USB debugging enabled and its RSA
  authorization accepted.

## Stage 1 source safety

The scanner is read-only. It lists regular files, reads their size and modified
time, and classifies photo/video/other extensions for the scan summary. It does
not pull, hash, modify, or delete phone files. Symbolic links are counted and
logged as skipped; their targets are never followed. Overlapping folders are
deduplicated by absolute phone path.

`Android/data` and `Android/obb` are excluded for all sources, including full
internal storage and SD-card scans. They are pruned on the phone before descent,
so their contents are not enumerated and do not create permission-error
warnings. A selected root inside either subtree is silently skipped.
`Android/media` remains eligible.

WhatsApp sources point only at these media trees:

- `/sdcard/WhatsApp/Media`
- `/sdcard/Android/media/com.whatsapp/WhatsApp/Media`

The scanner does not select the sibling `Databases` or `Backups` folders.
Other defaults are DCIM, Pictures, Movies, Download, Documents, Music,
Recordings, legacy/shared Telegram media, entire `/sdcard`, and mounted
`/storage/XXXX-XXXX` SD-card roots. Custom paths are limited to shared storage.

## Stage 2 backup and signing

`BackupEngine` hashes each phone file with `sha256sum` before pulling. It uses
`adb pull -a` to a unique `.part` file, hashes the local result, and installs it
only after a match. If device `sha256sum` is unavailable, it performs two pulls
and requires both local hashes to match. By default, up to three retries are
made after the initial attempt. Existing untracked destination files are never
overwritten; they are adopted only if they match the live phone. Resume skips a
file only when the signed manifest entry and local size/hash match and a fresh
phone stat/hash still agrees with the current scan. Scan warnings prevent a
backup from being marked fully verified, even if every listed file matches.

The Ed25519 private key and its local public-key trust reference are kept under
per-user app data, never in a backup. A password-protected private key is
supported on any platform. Without a password, Windows uses current-user DPAPI;
if DPAPI is unavailable, the key store fails closed rather than writing a
plaintext private key. Each backup contains `manifest.json`, `manifest.sig`, and
`public_key.pem` (the public key), plus its files and `backup_log.txt`.

## Run tests

From the repository root:

```powershell
python -m unittest discover -s phone_media_vault/tests -v
```

There is no `main.py` yet. The `python main.py` application launch instructions
will be added with the WebView GUI, before packaging.
