from __future__ import annotations

import json
import unittest
from pathlib import Path

from phone_media_vault.core.report import render_verification_report, write_verification_report
from phone_media_vault.core.verifier import FileStatus, safe_manifest_path, verify_backup
from phone_media_vault.tests._helpers import BackupFixture


class VerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = BackupFixture()
        self.result = self.fx.make_backup()

    def tearDown(self) -> None:
        self.fx.cleanup()

    def _first_file(self) -> Path:
        entry = self.result.manifest["files"][0]
        return self.fx.backup_dir / entry["relative_path"]

    def test_clean_backup_is_complete(self) -> None:
        report = verify_backup(self.fx.backup_dir, trusted_public_key_bytes=self.fx.trusted_key)
        self.assertTrue(report.signature_valid)
        self.assertTrue(report.public_key_trusted)
        self.assertTrue(report.complete)
        self.assertEqual(report.ok_count, self.result.files_total)
        self.assertEqual(report.extra_files, [])

    def test_detects_modified_missing_and_extra_files(self) -> None:
        target = self._first_file()
        data = bytearray(target.read_bytes())
        data[0] ^= 0xFF
        target.write_bytes(bytes(data))
        second = self.fx.backup_dir / self.result.manifest["files"][1]["relative_path"]
        second.unlink()
        (self.fx.backup_dir / "files" / "stray.bin").write_bytes(b"x")
        (self.fx.backup_dir / "files" / ".left.part").write_bytes(b"x")

        report = verify_backup(self.fx.backup_dir, trusted_public_key_bytes=self.fx.trusted_key)

        statuses = {check.status for check in report.damaged_checks}
        self.assertEqual(statuses, {FileStatus.MODIFIED, FileStatus.MISSING})
        self.assertFalse(report.intact)
        self.assertEqual(report.extra_files, ["files/stray.bin"])
        self.assertEqual(report.leftover_part_files, ["files/.left.part"])

    def test_size_only_mode_skips_hashing(self) -> None:
        target = self._first_file()
        data = bytearray(target.read_bytes())
        data[0] ^= 0xFF
        target.write_bytes(bytes(data))
        report = verify_backup(self.fx.backup_dir, check_hashes=False)
        self.assertTrue(report.intact)  # same size: only a full check finds it

    def test_tampered_manifest_invalidates_signature(self) -> None:
        manifest_path = self.fx.backup_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["files"][0]["sha256"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest))
        report = verify_backup(self.fx.backup_dir)
        self.assertFalse(report.signature_valid)
        self.assertFalse(report.intact)

    def test_untrusted_key_is_reported(self) -> None:
        report = verify_backup(self.fx.backup_dir, trusted_public_key_bytes=b"other key")
        self.assertFalse(report.public_key_trusted)
        self.assertFalse(report.intact)

    def test_missing_manifest(self) -> None:
        report = verify_backup(self.fx.root)
        self.assertFalse(report.manifest_present)
        self.assertFalse(report.intact)

    def test_safe_manifest_path_rejects_traversal(self) -> None:
        for bad in ("../x", "/etc/passwd", "files/../../x", "other/x", "files\\..\\x", "files/C:x", ""):
            with self.assertRaises(ValueError, msg=bad):
                safe_manifest_path(self.fx.backup_dir, bad)
        self.assertTrue(str(safe_manifest_path(self.fx.backup_dir, "files/internal/a.jpg")).endswith("a.jpg"))

    def test_html_report_is_escaped_and_written(self) -> None:
        report = verify_backup(self.fx.backup_dir, trusted_public_key_bytes=self.fx.trusted_key)
        html = render_verification_report(report, app_version="1.0")
        self.assertIn('dir="rtl"', html)
        self.assertIn("سليمة بالكامل", html)
        path = write_verification_report(report)
        self.assertTrue(path.is_file())
        # The report itself is a reserved file, not an untracked extra.
        self.assertEqual(verify_backup(self.fx.backup_dir).extra_files, [])


if __name__ == "__main__":
    unittest.main()
