from __future__ import annotations

import unittest

from phone_media_vault.core.adb_manager import (
    AdbCommandError,
    AdbCommandResult,
    AdbManager,
    AdbTransportError,
)
from phone_media_vault.core.models import MediaCategory
from phone_media_vault.core.scanner import classify_file


class AdbManagerParsingTests(unittest.TestCase):
    def test_parse_devices_includes_state_and_device_properties(self) -> None:
        output = """List of devices attached
ABC123 device product:pixel_8 model:Pixel_8 device:shiba transport_id:4
XYZ987 unauthorized usb:1-1
EMU offline product:sdk model:sdk_gphone64_x86_64 device:emu64x
"""

        devices = AdbManager.parse_devices(output)

        self.assertEqual([device.serial for device in devices], ["ABC123", "XYZ987", "EMU"])
        self.assertEqual(devices[0].state, "device")
        self.assertEqual(devices[0].model, "Pixel 8")
        self.assertEqual(devices[0].product, "pixel 8")
        self.assertEqual(devices[0].transport_id, "4")
        self.assertEqual(devices[1].state, "unauthorized")
        self.assertEqual(devices[2].state, "offline")

    def test_parse_nul_listing_preserves_unicode_and_newline_in_phone_path(self) -> None:
        phone_path = "/sdcard/Pictures/صورة\nنسخة.jpg".encode("utf-8")
        payload = b"F\x0042\x001712345678\x00" + phone_path + b"\x00"

        listing = AdbManager.parse_remote_file_listing(payload)

        self.assertEqual(len(listing.files), 1)
        self.assertEqual(listing.files[0].path, phone_path.decode("utf-8"))
        self.assertEqual(listing.files[0].size, 42)
        self.assertEqual(listing.files[0].modified_time, 1712345678)
        self.assertEqual(listing.warnings, [])

    def test_parse_remote_listing_keeps_per_file_stat_issues(self) -> None:
        payload = (
            b"E\x00/sdcard/DCIM/unreadable.jpg\x00"
            b"L\x00/sdcard/DCIM/shortcut.jpg\x00"
        )

        listing = AdbManager.parse_remote_file_listing(payload)

        self.assertEqual(len(listing.issues), 1)
        self.assertEqual(listing.issues[0].path, "/sdcard/DCIM/unreadable.jpg")
        self.assertEqual(listing.symlinks, ["/sdcard/DCIM/shortcut.jpg"])
        self.assertEqual(listing.files, [])

    def test_rejects_relative_and_traversal_phone_paths(self) -> None:
        with self.assertRaises(ValueError):
            AdbManager.validate_phone_path("sdcard/DCIM")
        with self.assertRaises(ValueError):
            AdbManager.validate_phone_path("/sdcard/../data")

    def test_normalizes_android_posix_path_independent_of_host(self) -> None:
        self.assertEqual(
            AdbManager.validate_phone_path("/sdcard/DCIM/Camera/"),
            "/sdcard/DCIM/Camera",
        )


class AdbReadOperationTests(unittest.TestCase):
    def _manager_with_shell_result(self, result: AdbCommandResult) -> AdbManager:
        manager = object.__new__(AdbManager)
        manager.run_shell = lambda serial, command, *, check=True, timeout=None: result
        return manager

    def test_remote_sha256_parses_device_digest(self) -> None:
        digest = "ab" * 32
        manager = self._manager_with_shell_result(
            AdbCommandResult(0, f"{digest}  /sdcard/file.jpg\n".encode(), b"")
        )
        self.assertEqual(manager.remote_sha256("SERIAL", "/sdcard/file.jpg"), digest)

    def test_remote_sha256_returns_none_only_when_utility_is_missing(self) -> None:
        manager = self._manager_with_shell_result(
            AdbCommandResult(
                127,
                b"",
                b"sh: sha256sum: inaccessible or not found",
            )
        )
        self.assertIsNone(manager.remote_sha256("SERIAL", "/sdcard/file.jpg"))

        missing_file = self._manager_with_shell_result(
            AdbCommandResult(
                1,
                b"",
                b"sha256sum: /sdcard/missing.jpg: No such file or directory",
            )
        )
        with self.assertRaises(AdbCommandError):
            missing_file.remote_sha256("SERIAL", "/sdcard/missing.jpg")

    def test_remote_stat_parses_size_and_epoch_time(self) -> None:
        manager = self._manager_with_shell_result(
            AdbCommandResult(0, b"1234 1710000000\r\n", b"")
        )
        self.assertEqual(manager.remote_stat("SERIAL", "/sdcard/file.jpg"), (1234, 1710000000))

    def test_recursive_listing_enforces_android_data_and_obb_exclusions(self) -> None:
        manager = object.__new__(AdbManager)
        commands: list[str] = []

        def fake_exec_out(serial, command, *, check=True, timeout=None):
            commands.append(command)
            return AdbCommandResult(0, b"", b"")

        manager.run_exec_out = fake_exec_out
        manager.list_file_stats("SERIAL", "/storage/ABCD-1234")
        self.assertIn("/storage/ABCD-1234/Android/data", commands[0])
        self.assertIn("/storage/ABCD-1234/Android/obb", commands[0])
        self.assertIn("-prune", commands[0])

        # Direct calls on an excluded subtree return silently without probing
        # the phone, while Android/media remains an eligible source.
        excluded = manager.list_file_stats(
            "SERIAL", "/storage/ABCD-1234/Android/data/app"
        )
        self.assertEqual(excluded.files, [])
        self.assertEqual(excluded.warnings, [])
        self.assertEqual(len(commands), 1)

        manager.list_file_stats(
            "SERIAL", "/storage/ABCD-1234/Android/media"
        )
        self.assertEqual(len(commands), 2)
        self.assertNotIn("-prune", commands[1])

    def test_pull_uses_timestamp_preservation_and_argument_list(self) -> None:
        manager = object.__new__(AdbManager)
        seen: dict[str, object] = {}

        def fake_run_raw(arguments, *, serial=None, timeout=None):
            seen["arguments"] = tuple(arguments)
            seen["serial"] = serial
            seen["timeout"] = timeout
            return AdbCommandResult(0, b"pulled", b"")

        manager._run_raw = fake_run_raw
        manager.pull_file(
            "SERIAL",
            "/sdcard/Pictures/صورة.jpg",
            "C:/backup/photo.part",
            preserve_timestamps=True,
        )

        self.assertEqual(seen["serial"], "SERIAL")
        self.assertEqual(
            seen["arguments"],
            ("pull", "-a", "/sdcard/Pictures/صورة.jpg", "C:/backup/photo.part"),
        )

    def test_transport_loss_is_distinguished_from_file_errors(self) -> None:
        manager = self._manager_with_shell_result(
            AdbCommandResult(1, b"", b"error: device offline")
        )
        with self.assertRaises(AdbTransportError):
            manager.remote_stat("SERIAL", "/sdcard/file.jpg")


class FileClassificationTests(unittest.TestCase):
    def test_photo_and_video_extensions_are_case_insensitive(self) -> None:
        self.assertIs(classify_file("/sdcard/DCIM/IMG_01.HEIC"), MediaCategory.PHOTO)
        self.assertIs(classify_file("/sdcard/Movies/clip.MP4"), MediaCategory.VIDEO)
        self.assertIs(classify_file("/sdcard/Documents/notes.PDF"), MediaCategory.OTHER)


if __name__ == "__main__":
    unittest.main()
