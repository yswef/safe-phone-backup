from __future__ import annotations

import shlex
import tempfile
import unittest
from pathlib import Path

from phone_media_vault.core.adb_manager import AdbCommandError, AdbCommandResult, AdbManager
from phone_media_vault.core.adb_writer import AdbWriter, PhoneWriteRefused


class RecordingAdb(AdbManager):
    def __init__(self, stdout: bytes = b"") -> None:  # skip adb discovery
        self.adb_path = "adb"
        self.command_timeout = 5.0
        self.calls: list[tuple[str, ...]] = []
        self.stdout = stdout

    def _run_raw(self, arguments, *, serial=None, timeout=None):
        self.calls.append(tuple(arguments))
        return AdbCommandResult(0, self.stdout, b"")


class AdbWriterTests(unittest.TestCase):
    def test_delete_quotes_path_and_refuses_non_files(self) -> None:
        adb = RecordingAdb(b"DELETED")
        evil = "/sdcard/DCIM/a'; rm -rf /sdcard; echo '.jpg"
        AdbWriter(adb).delete_file("SERIAL", evil)
        command = adb.calls[0][1]
        self.assertIn(shlex.quote(evil), command)
        self.assertNotIn("rm -rf /sdcard;", command.replace(shlex.quote(evil), ""))
        self.assertNotIn(" -r", command.replace(shlex.quote(evil), ""))

        with self.assertRaises(AdbCommandError):
            AdbWriter(RecordingAdb(b"NOTFILE")).delete_file("SERIAL", "/sdcard/DCIM")

    def test_protected_paths_never_reach_adb(self) -> None:
        adb = RecordingAdb(b"DELETED")
        writer = AdbWriter(adb)
        for path in ("/sdcard/Android/data/app/x", "/data/local/tmp/x", "/sdcard"):
            with self.assertRaises((PhoneWriteRefused, ValueError)):
                writer.delete_file("SERIAL", path)
        self.assertEqual(adb.calls, [])

    def test_push_and_rename_use_argv_and_no_clobber(self) -> None:
        adb = RecordingAdb()
        writer = AdbWriter(adb)
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(b"x")
        try:
            writer.push_file("SERIAL", handle.name, "/sdcard/Restored/a b.jpg")
        finally:
            Path(handle.name).unlink()
        self.assertEqual(adb.calls[0], ("push", handle.name, "/sdcard/Restored/a b.jpg"))
        writer.rename("SERIAL", "/sdcard/Restored/.a.part", "/sdcard/Restored/a b.jpg")
        self.assertTrue(adb.calls[1][1].startswith("mv -n "))


if __name__ == "__main__":
    unittest.main()
