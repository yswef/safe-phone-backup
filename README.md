# Phone Media Vault (خزنة الوسائط)

Incremental Windows Android-media backup application. Development is proceeding
in confirmed stages.

- **Stage 1 complete:** read-only ADB manager, storage-source discovery, and
  recursive scanner. `Android/data` and `Android/obb` are excluded everywhere;
  WhatsApp sources target only `Media` subtrees and prune `Databases`/`Backups`;
  symbolic links are skipped.
- **Stage 2 complete:** verified backup engine, phone/local SHA-256 comparison,
  double-pull fallback, signed manifest, and protected Ed25519 key storage. A
  real-device smoke test is available at `tools/smoke_backup.py`.
- **Not implemented yet:** full backup-integrity verifier, restore, safe wipe,
  WebView GUI, installer, and final `python main.py` launch flow.

See [`phone_media_vault/README.md`](phone_media_vault/README.md) for setup and
test instructions.
