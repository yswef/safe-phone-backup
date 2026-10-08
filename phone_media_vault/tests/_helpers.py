"""Shared fixtures: a simulated phone plus a signed backup made from it."""

from __future__ import annotations

import tempfile
from pathlib import Path

from phone_media_vault.app.demo import DEMO_SD, DemoPhone
from phone_media_vault.core.backup_engine import BackupEngine
from phone_media_vault.core.models import SourceKind, StorageSource
from phone_media_vault.core.scanner import scan_sources
from phone_media_vault.core.signer import ManifestSigner, PrivateKeyStore


class FakeProtector:
    def available(self) -> bool:
        return True

    def protect(self, data: bytes) -> bytes:
        return bytes(byte ^ 0x5A for byte in data)

    def unprotect(self, data: bytes) -> bytes:
        return bytes(byte ^ 0x5A for byte in data)


INTERNAL = StorageSource(
    source_id="internal:entire", root_path="/sdcard", label_en="Internal", label_ar="الداخلية",
    kind=SourceKind.INTERNAL_STORAGE, volume_root="/sdcard",
)
SD = StorageSource(
    source_id="sd:demo", root_path=DEMO_SD, label_en="SD", label_ar="SD",
    kind=SourceKind.SD_CARD, volume_root=DEMO_SD, removable=True,
)


class BackupFixture:
    """Create ``root/phone``, ``root/keys``, and a fully verified ``root/backup``."""

    def __init__(self, *, sha256_available: bool = True) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="pmv-test-")
        self.root = Path(self._tmp.name)
        self.phone = DemoPhone(self.root / "phone", sha256_available=sha256_available)
        self.store = PrivateKeyStore(self.root / "keys" / "ed25519-private.key", protector=FakeProtector())
        self.signer = ManifestSigner(self.store)
        self.backup_dir = self.root / "backup"
        self.serial = self.phone.device().serial

    def make_backup(self, sources=(INTERNAL, SD)):
        scan = scan_sources(self.phone, self.serial, list(sources))
        result = BackupEngine(self.phone, self.signer).backup(
            self.serial, self.phone.device(), scan, self.backup_dir
        )
        assert result.fully_verified, result.failed_files
        return result

    @property
    def trusted_key(self) -> bytes:
        return self.signer.trusted_public_key_path.read_bytes()

    def cleanup(self) -> None:
        self._tmp.cleanup()
