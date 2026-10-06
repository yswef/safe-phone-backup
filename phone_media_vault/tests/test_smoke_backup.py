from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from phone_media_vault.core.models import MediaCategory, ScannedFile
from tools.smoke_backup import (
    _tamper_test_copy,
    manifest_local_path,
    select_first_files,
    verify_file_entry,
)


class SmokeBackupHelperTests(unittest.TestCase):
    @staticmethod
    def _scanned_file(phone_path: str) -> ScannedFile:
        return ScannedFile(
            phone_path=phone_path,
            relative_path="unused",
            size=1,
            modified_time=1,
            category=MediaCategory.OTHER,
            source_id="test",
        )

    def test_selects_at_most_ten_files_in_stable_path_order(self) -> None:
        files = [
            self._scanned_file(f"/sdcard/Folder/{index:02}.bin")
            for index in range(12)
        ]
        selected = select_first_files(list(reversed(files)))
        self.assertEqual(len(selected), 10)
        self.assertEqual(
            [item.phone_path for item in selected],
            [f"/sdcard/Folder/{index:02}.bin" for index in range(10)],
        )
        with self.assertRaises(ValueError):
            select_first_files(files, 11)

    def test_manifest_file_hash_check_and_tamper_test(self) -> None:
        original = b"verified smoke-test copy"
        entry = {
            "size": len(original),
            "sha256": hashlib.sha256(original).hexdigest(),
        }
        with tempfile.TemporaryDirectory() as temporary:
            backup_file = Path(temporary) / "photo.jpg"
            backup_file.write_bytes(original)

            self.assertTrue(verify_file_entry(backup_file, entry))
            detected, message = _tamper_test_copy(backup_file, entry)

            self.assertTrue(detected, message)
            self.assertEqual(backup_file.read_bytes(), original)

    def test_manifest_paths_cannot_escape_backup_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            backup_directory = Path(temporary) / "backup"
            backup_directory.mkdir()

            with self.assertRaises(ValueError):
                manifest_local_path(backup_directory, "../outside.txt")
            with self.assertRaises(ValueError):
                manifest_local_path(backup_directory, "/outside.txt")


if __name__ == "__main__":
    unittest.main()
