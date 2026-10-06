from __future__ import annotations

import hashlib
import json
import threading
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from phone_media_vault.core.adb_manager import AdbCommandError
from phone_media_vault.core.backup_engine import (
    BackupDestinationError,
    BackupEngine,
    FileBackupError,
    _target_relative_path,
    serialize_manifest,
)
from phone_media_vault.core.models import (
    DeviceInfo,
    MediaCategory,
    ScanResult,
    ScanWarning,
    ScannedFile,
)
from phone_media_vault.core.signer import (
    ManifestSigner,
    PrivateKeyStore,
    SigningError,
)


class FakeProtector:
    def available(self) -> bool:
        return True

    def protect(self, data: bytes) -> bytes:
        return bytes(byte ^ 0xA5 for byte in data)

    def unprotect(self, data: bytes) -> bytes:
        return bytes(byte ^ 0xA5 for byte in data)


class MockAdb:
    def __init__(self, files: dict[str, bytes], *, sha_available: bool = True) -> None:
        self.files = dict(files)
        self.sha_available = sha_available
        self.pull_count: dict[str, int] = {}
        self.pull_responses: dict[str, list[bytes]] = {}
        self.sha_responses: dict[str, list[str | None]] = {}
        self.mtimes: dict[str, int] = {}
        self.stat_errors: set[str] = set()

    def remote_stat(self, serial: str, phone_path: str) -> tuple[int, int] | None:
        if phone_path in self.stat_errors:
            raise AdbCommandError("permission denied", phone_path)
        payload = self.files[phone_path]
        return len(payload), self.mtimes.get(phone_path, 1710000000)

    def remote_sha256(self, serial: str, phone_path: str) -> str | None:
        responses = self.sha_responses.get(phone_path)
        if responses:
            response = responses.pop(0)
            if response is not None:
                return response
            if not self.sha_available:
                return None
        if not self.sha_available:
            return None
        return hashlib.sha256(self.files[phone_path]).hexdigest()

    def pull_file(
        self,
        serial: str,
        phone_path: str,
        local_path: str | Path,
        *,
        preserve_timestamps: bool = True,
        timeout: float | None = None,
    ) -> None:
        self.pull_count[phone_path] = self.pull_count.get(phone_path, 0) + 1
        responses = self.pull_responses.get(phone_path)
        if responses:
            content = responses.pop(0)
        else:
            content = self.files[phone_path]
        target = Path(local_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


class BackupEngineTests(unittest.TestCase):
    SERIAL = "USB-DEVICE-001"
    DEVICE = DeviceInfo(
        serial=SERIAL,
        state="device",
        model="Example Phone",
        android_version="15",
    )

    def _make_signer(self, root: Path) -> tuple[ManifestSigner, Path]:
        key_path = root / "local-app-data" / "keys" / "ed25519-private.key"
        store = PrivateKeyStore(key_path, protector=FakeProtector())
        return ManifestSigner(store), key_path

    @staticmethod
    def _file(phone_path: str, content: bytes, mtime: int = 1710000000) -> ScannedFile:
        return ScannedFile(
            phone_path=phone_path,
            relative_path="DCIM/placeholder.jpg",
            size=len(content),
            modified_time=mtime,
            category=MediaCategory.PHOTO,
            source_id="folder:dcim",
        )

    def test_backup_hashes_pulls_builds_manifest_and_signs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phone_path = "/sdcard/DCIM/CON: summer% photo.jpg"
            content = b"verified camera bytes"
            adb = MockAdb({phone_path: content})
            signer, key_path = self._make_signer(root)
            backup_directory = root / "backups" / "backup-01"
            item = self._file(phone_path, content)

            result = BackupEngine(adb, signer, app_version="1.2.3").backup(
                self.SERIAL,
                self.DEVICE,
                [item],
                backup_directory,
                hash_serial=True,
            )

            self.assertTrue(result.fully_verified)
            self.assertEqual(result.verified_count, 1)
            self.assertEqual(result.failed_count, 0)
            entry = result.manifest["files"][0]
            self.assertEqual(entry["original_phone_path"], phone_path)
            self.assertEqual(entry["size"], len(content))
            self.assertEqual(entry["modified_time"], 1710000000)
            self.assertEqual(entry["verification_method"], "phone-sha256")
            self.assertEqual(entry["status"], "verified")
            self.assertEqual(entry["sha256"], hashlib.sha256(content).hexdigest())
            self.assertIn("%3A", entry["relative_path"])
            self.assertIn("%25", entry["relative_path"])
            restored_local_path = backup_directory.joinpath(
                *Path(entry["relative_path"]).parts
            )
            self.assertEqual(restored_local_path.read_bytes(), content)
            self.assertTrue(ManifestSigner.verify_backup_directory(backup_directory))
            self.assertTrue(key_path.is_file())
            self.assertNotEqual(key_path.parent, backup_directory)
            self.assertEqual(result.manifest["device"]["serial_hashed"], True)
            self.assertNotEqual(result.manifest["device"]["serial"], self.SERIAL)
            self.assertTrue((backup_directory / "public_key.pem").is_file())
            self.assertTrue((backup_directory / "backup_log.txt").is_file())
            self.assertFalse(any("private.key" in p.name for p in backup_directory.rglob("*")))

    def test_sha256_unavailable_falls_back_to_two_matching_pulls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phone_path = "/sdcard/Pictures/image.png"
            content = b"double pull contents"
            adb = MockAdb({phone_path: content}, sha_available=False)
            signer, _ = self._make_signer(root)
            result = BackupEngine(adb, signer).backup(
                self.SERIAL,
                self.DEVICE,
                [self._file(phone_path, content)],
                root / "backup",
            )

            self.assertTrue(result.fully_verified)
            self.assertEqual(adb.pull_count[phone_path], 2)
            self.assertEqual(
                result.manifest["files"][0]["verification_method"],
                "verified-by-double-pull",
            )
            self.assertTrue(ManifestSigner.verify_backup_directory(root / "backup"))

    def test_hash_mismatch_retries_then_installs_only_verified_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phone_path = "/sdcard/Movies/clip.mp4"
            content = b"correct-video-content"
            adb = MockAdb({phone_path: content})
            adb.pull_responses[phone_path] = [b"corrupt first pull", content]
            signer, _ = self._make_signer(root)
            result = BackupEngine(adb, signer, max_retries=2).backup(
                self.SERIAL,
                self.DEVICE,
                [self._file(phone_path, content)],
                root / "backup",
            )

            self.assertTrue(result.fully_verified)
            self.assertEqual(adb.pull_count[phone_path], 2)
            entry = result.manifest["files"][0]
            destination = root / "backup" / entry["relative_path"]
            self.assertEqual(destination.read_bytes(), content)
            self.assertEqual(entry["status"], "verified")

    def test_failed_hash_checks_never_install_a_partial_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phone_path = "/sdcard/Movies/broken.mp4"
            content = b"the real file"
            adb = MockAdb({phone_path: content})
            adb.pull_responses[phone_path] = [b"wrong 1", b"wrong 2", b"wrong 3"]
            signer, _ = self._make_signer(root)
            backup_directory = root / "backup"
            result = BackupEngine(adb, signer, max_retries=2).backup(
                self.SERIAL,
                self.DEVICE,
                [self._file(phone_path, content)],
                backup_directory,
            )

            self.assertFalse(result.fully_verified)
            self.assertEqual(result.failed_count, 1)
            self.assertEqual(adb.pull_count[phone_path], 3)
            entry = result.manifest["files"][0]
            self.assertEqual(entry["status"], "failed")
            self.assertFalse((backup_directory / entry["relative_path"]).exists())
            self.assertTrue(ManifestSigner.verify_backup_directory(backup_directory))
            self.assertFalse(list(backup_directory.rglob("*.part")))

    def test_resume_skips_file_only_when_signed_manifest_size_and_hash_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phone_path = "/sdcard/DCIM/resume.jpg"
            content = b"resume-me"
            adb = MockAdb({phone_path: content})
            signer, _ = self._make_signer(root)
            backup_directory = root / "backup"
            item = self._file(phone_path, content)
            engine = BackupEngine(adb, signer)

            first = engine.backup(self.SERIAL, self.DEVICE, [item], backup_directory)
            pulls_after_first = adb.pull_count[phone_path]
            second = engine.backup(self.SERIAL, self.DEVICE, [item], backup_directory)

            self.assertTrue(first.fully_verified)
            self.assertTrue(second.fully_verified)
            self.assertEqual(second.skipped_count, 1)
            self.assertEqual(adb.pull_count[phone_path], pulls_after_first)
            self.assertTrue(ManifestSigner.verify_backup_directory(backup_directory))

    def test_resume_does_not_skip_when_phone_source_changed_since_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phone_path = "/sdcard/DCIM/resume-changed.jpg"
            scanned_content = b"content from the scan"
            changed_content = b"a newer phone version with another size"
            adb = MockAdb({phone_path: scanned_content})
            signer, _ = self._make_signer(root)
            backup_directory = root / "backup"
            item = self._file(phone_path, scanned_content)
            engine = BackupEngine(adb, signer)

            first = engine.backup(self.SERIAL, self.DEVICE, [item], backup_directory)
            local_path = backup_directory / first.manifest["files"][0]["relative_path"]
            pulls_after_first = adb.pull_count[phone_path]
            adb.files[phone_path] = changed_content
            adb.mtimes[phone_path] = item.modified_time + 1

            resumed = engine.backup(
                self.SERIAL, self.DEVICE, [item], backup_directory
            )

            self.assertTrue(first.fully_verified)
            self.assertEqual(resumed.failed_count, 1)
            self.assertFalse(resumed.fully_verified)
            self.assertEqual(adb.pull_count[phone_path], pulls_after_first)
            self.assertEqual(local_path.read_bytes(), scanned_content)

    def test_existing_untracked_log_is_not_modified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phone_path = "/sdcard/DCIM/log-safety.jpg"
            content = b"phone content"
            adb = MockAdb({phone_path: content})
            signer, _ = self._make_signer(root)
            backup_directory = root / "backup"
            backup_directory.mkdir()
            log_path = backup_directory / "backup_log.txt"
            log_path.write_bytes(b"user-owned log\n")

            with self.assertRaises(BackupDestinationError):
                BackupEngine(adb, signer).backup(
                    self.SERIAL,
                    self.DEVICE,
                    [self._file(phone_path, content)],
                    backup_directory,
                )

            self.assertEqual(log_path.read_bytes(), b"user-owned log\n")
            self.assertEqual(adb.pull_count.get(phone_path, 0), 0)

    def test_existing_untracked_destination_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phone_path = "/sdcard/DCIM/collision.jpg"
            content = b"expected phone bytes"
            adb = MockAdb({phone_path: content})
            signer, _ = self._make_signer(root)
            backup_directory = root / "backup"
            relative_path = _target_relative_path(phone_path)
            target = backup_directory / relative_path
            target.parent.mkdir(parents=True)
            target.write_bytes(b"user data already here")

            result = BackupEngine(adb, signer).backup(
                self.SERIAL,
                self.DEVICE,
                [self._file(phone_path, content)],
                backup_directory,
            )

            self.assertEqual(result.failed_count, 1)
            self.assertEqual(target.read_bytes(), b"user data already here")
            self.assertEqual(adb.pull_count.get(phone_path, 0), 0)

    def test_source_change_since_scan_is_failed_without_pull(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phone_path = "/sdcard/DCIM/changed.jpg"
            content = b"current content"
            adb = MockAdb({phone_path: content})
            adb.mtimes[phone_path] = 1710000001
            signer, _ = self._make_signer(root)
            result = BackupEngine(adb, signer).backup(
                self.SERIAL,
                self.DEVICE,
                [self._file(phone_path, content, mtime=1710000000)],
                root / "backup",
            )

            self.assertEqual(result.failed_count, 1)
            self.assertEqual(adb.pull_count.get(phone_path, 0), 0)
            self.assertEqual(result.manifest["files"][0]["status"], "failed")

    def test_per_file_adb_permission_failure_does_not_abort_other_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            denied_path = "/sdcard/Documents/blocked.pdf"
            good_path = "/sdcard/Documents/good.pdf"
            denied_bytes = b"denied"
            good_bytes = b"available"
            adb = MockAdb({denied_path: denied_bytes, good_path: good_bytes})
            adb.stat_errors.add(denied_path)
            signer, _ = self._make_signer(root)
            items = [
                self._file(denied_path, denied_bytes),
                self._file(good_path, good_bytes),
            ]

            result = BackupEngine(adb, signer).backup(
                self.SERIAL, self.DEVICE, items, root / "backup"
            )

            self.assertEqual(result.failed_count, 1)
            self.assertEqual(result.verified_count, 1)
            self.assertEqual(adb.pull_count.get(denied_path, 0), 0)
            self.assertEqual(adb.pull_count.get(good_path, 0), 1)
            statuses = {
                entry["original_phone_path"]: entry["status"]
                for entry in result.manifest["files"]
            }
            self.assertEqual(statuses[denied_path], "failed")
            self.assertEqual(statuses[good_path], "verified")

    def test_cancelled_backup_writes_signed_pending_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phone_path = "/sdcard/DCIM/cancel.jpg"
            content = b"cancelled"
            adb = MockAdb({phone_path: content})
            signer, _ = self._make_signer(root)
            cancel = threading.Event()
            cancel.set()

            result = BackupEngine(adb, signer).backup(
                self.SERIAL,
                self.DEVICE,
                [self._file(phone_path, content)],
                root / "backup",
                cancel_event=cancel,
            )

            self.assertTrue(result.cancelled)
            self.assertFalse(result.fully_verified)
            self.assertEqual(result.manifest["files"][0]["status"], "pending")
            self.assertTrue(ManifestSigner.verify_backup_directory(root / "backup"))
            self.assertEqual(adb.pull_count.get(phone_path, 0), 0)

    def test_scan_warnings_prevent_fully_verified_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phone_path = "/sdcard/DCIM/photo.jpg"
            content = b"verified, but scan had a skipped item"
            adb = MockAdb({phone_path: content})
            signer, _ = self._make_signer(root)
            scan = ScanResult(
                files=[self._file(phone_path, content)],
                warnings=[
                    ScanWarning(
                        message_ar="تم تخطي رابط رمزي.",
                        source_id="folder:dcim",
                        phone_path="/sdcard/DCIM/link.jpg",
                    )
                ],
            )

            result = BackupEngine(adb, signer).backup(
                self.SERIAL, self.DEVICE, scan, root / "backup"
            )

            self.assertEqual(result.verified_count, 1)
            self.assertEqual(len(result.scan_warnings), 1)
            self.assertFalse(result.fully_verified)

    def test_install_fallback_copies_when_hardlinks_are_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            temporary_file = root / ".photo.part"
            destination = root / "photo.jpg"
            temporary_file.write_bytes(b"verified content")

            with patch(
                "phone_media_vault.core.backup_engine.os.link",
                side_effect=OSError("hard links unavailable"),
            ):
                BackupEngine._install_new_file(temporary_file, destination)

            self.assertEqual(destination.read_bytes(), b"verified content")
            self.assertFalse(temporary_file.exists())

    def test_install_fallback_never_replaces_concurrent_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            temporary_file = root / ".photo.part"
            destination = root / "photo.jpg"
            temporary_file.write_bytes(b"verified content")

            def create_racing_destination(source: Path, target: Path) -> None:
                target.write_bytes(b"user data")
                raise OSError("hard links unavailable")

            with patch(
                "phone_media_vault.core.backup_engine.os.link",
                side_effect=create_racing_destination,
            ):
                with self.assertRaises(FileBackupError):
                    BackupEngine._install_new_file(temporary_file, destination)

            self.assertEqual(destination.read_bytes(), b"user data")
            self.assertEqual(temporary_file.read_bytes(), b"verified content")

    def test_engine_refuses_private_key_path_inside_backup_before_key_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            backup_directory = root / "backup"
            forbidden_key = backup_directory / "private.key"
            signer = ManifestSigner(
                PrivateKeyStore(forbidden_key, protector=FakeProtector())
            )
            adb = MockAdb({})

            with self.assertRaises(BackupDestinationError):
                BackupEngine(adb, signer).backup(
                    self.SERIAL,
                    self.DEVICE,
                    [],
                    backup_directory,
                )

            self.assertFalse(forbidden_key.exists())

    def test_manifest_serialization_is_deterministic(self) -> None:
        left = {"b": 2, "a": 1}
        right = {"a": 1, "b": 2}
        self.assertEqual(serialize_manifest(left), serialize_manifest(right))


if __name__ == "__main__":
    unittest.main()
