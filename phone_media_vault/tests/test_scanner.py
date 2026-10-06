from __future__ import annotations

import unittest

from phone_media_vault.core.models import (
    MediaCategory,
    RemoteFileStat,
    RemoteListing,
    SourceKind,
    StorageSource,
)
from phone_media_vault.core.scanner import (
    custom_source,
    discover_sources,
    scan_sources,
)


class FakeAdb:
    def __init__(self) -> None:
        self.directories = {
            "/sdcard",
            "/sdcard/DCIM",
            "/sdcard/Download",
            "/sdcard/WhatsApp/Media",
            "/sdcard/Android/media/com.whatsapp/WhatsApp/Media",
            "/sdcard/Custom",
            "/storage/1234-abcd",
        }
        self.listings: dict[str, RemoteListing] = {
            "/sdcard": RemoteListing(
                files=[
                    RemoteFileStat("/sdcard/DCIM/Camera/a.jpg", 100, 1710000000),
                    RemoteFileStat("/sdcard/Download/readme.pdf", 20, 1710000001),
                ]
            ),
            "/sdcard/DCIM": RemoteListing(
                files=[RemoteFileStat("/sdcard/DCIM/Camera/a.jpg", 100, 1710000000)]
            ),
            "/sdcard/Download": RemoteListing(
                files=[RemoteFileStat("/sdcard/Download/readme.pdf", 20, 1710000001)]
            ),
            "/storage/1234-abcd": RemoteListing(
                files=[RemoteFileStat("/storage/1234-abcd/Movies/b.MP4", 200, 1710000002)]
            ),
            "/sdcard/Custom": RemoteListing(
                files=[RemoteFileStat("/sdcard/Custom/one.bin", 1, 1)]
            ),
        }
        self.excluded_paths_by_root: dict[str, tuple[str, ...]] = {}
        self.directory_checks: list[str] = []

    def is_directory(self, serial: str, phone_path: str) -> bool:
        self._check_serial(serial)
        self.directory_checks.append(phone_path)
        return phone_path in self.directories

    def list_directories(self, serial: str, phone_path: str) -> list[str]:
        self._check_serial(serial)
        if phone_path == "/storage":
            return ["/storage/emulated", "/storage/1234-abcd", "/storage/self"]
        return []

    def list_sd_card_roots(self, serial: str) -> list[str]:
        self._check_serial(serial)
        return ["/storage/1234-abcd"]

    def list_file_stats(
        self,
        serial: str,
        root_path: str,
        *,
        timeout: float | None = None,
        excluded_paths: tuple[str, ...] | list[str] = (),
    ) -> RemoteListing:
        self._check_serial(serial)
        self.excluded_paths_by_root[root_path] = tuple(excluded_paths)
        return self.listings.get(root_path, RemoteListing())

    @staticmethod
    def _check_serial(serial: str) -> None:
        if serial != "PHONE-1":
            raise AssertionError("scanner must use the explicitly selected device")


class SourceDiscoveryTests(unittest.TestCase):
    def test_discovers_existing_defaults_internal_storage_and_sd_card(self) -> None:
        sources = discover_sources(FakeAdb(), "PHONE-1")

        by_path = {source.root_path: source for source in sources}
        self.assertIn("/sdcard", by_path)
        self.assertIn("/sdcard/DCIM", by_path)
        self.assertIn("/sdcard/WhatsApp/Media", by_path)
        self.assertIn(
            "/sdcard/Android/media/com.whatsapp/WhatsApp/Media", by_path
        )
        self.assertNotIn("/sdcard/WhatsApp", by_path)
        self.assertNotIn("/sdcard/Android/media/com.whatsapp", by_path)
        self.assertIn("/storage/1234-abcd", by_path)
        self.assertNotIn("/sdcard/Pictures", by_path)
        self.assertIs(by_path["/sdcard"].kind, SourceKind.INTERNAL_STORAGE)
        self.assertIs(by_path["/storage/1234-abcd"].kind, SourceKind.SD_CARD)
        self.assertTrue(by_path["/storage/1234-abcd"].removable)

    def test_custom_source_requires_absolute_non_traversing_path(self) -> None:
        source = custom_source("/sdcard/Some Folder")
        self.assertIs(source.kind, SourceKind.CUSTOM)
        self.assertEqual(source.root_path, "/sdcard/Some Folder")
        self.assertEqual(source.volume_root, "/sdcard")
        self.assertIs(custom_source("/storage/1234-abcd/Pictures").kind, SourceKind.CUSTOM)
        self.assertEqual(custom_source("/sdcard/Android").root_path, "/sdcard/Android")
        self.assertEqual(
            custom_source("/sdcard/WhatsApp/Media").root_path,
            "/sdcard/WhatsApp/Media",
        )
        self.assertEqual(
            custom_source(
                "/sdcard/Android/media/com.whatsapp/WhatsApp/Media"
            ).root_path,
            "/sdcard/Android/media/com.whatsapp/WhatsApp/Media",
        )
        for unsafe_path in (
            "/sdcard/../private",
            "/data/data/com.example.app",
            "/sdcard",
            "/sdcard/Android/data/com.example.app",
            "/sdcard/Android/obb/com.example.app",
            "/sdcard/WhatsApp",
            "/sdcard/WhatsApp/Databases",
            "/sdcard/WhatsApp/Backups",
            "/sdcard/Android/media/com.whatsapp",
            "/sdcard/Android/media/com.whatsapp/WhatsApp",
            "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases",
            "/sdcard/Android/media/com.whatsapp/WhatsApp/Backups",
        ):
            with self.subTest(path=unsafe_path), self.assertRaises(ValueError):
                custom_source(unsafe_path)


class ScanTests(unittest.TestCase):
    def test_scans_and_deduplicates_overlapping_sources_with_breakdown(self) -> None:
        adb = FakeAdb()
        sources = [
            StorageSource(
                source_id="internal",
                root_path="/sdcard",
                label_en="Internal",
                label_ar="الداخلية",
                kind=SourceKind.INTERNAL_STORAGE,
                volume_root="/sdcard",
            ),
            StorageSource(
                source_id="dcim",
                root_path="/sdcard/DCIM",
                label_en="DCIM",
                label_ar="الكاميرا",
                volume_root="/sdcard",
            ),
            StorageSource(
                source_id="card",
                root_path="/storage/1234-abcd",
                label_en="SD card",
                label_ar="بطاقة SD",
                kind=SourceKind.SD_CARD,
                volume_root="/storage/1234-abcd",
                removable=True,
            ),
        ]

        result = scan_sources(adb, "PHONE-1", sources)

        self.assertEqual(result.total_files, 3)
        self.assertEqual(result.total_bytes, 320)
        self.assertEqual(result.photo_count, 1)
        self.assertEqual(result.video_count, 1)
        self.assertEqual(result.other_count, 1)
        self.assertEqual(result.photo_bytes, 100)
        self.assertEqual(result.video_bytes, 200)
        self.assertEqual(result.other_bytes, 20)
        by_phone_path = {item.phone_path: item for item in result.files}
        self.assertEqual(by_phone_path["/sdcard/DCIM/Camera/a.jpg"].relative_path, "DCIM/Camera/a.jpg")
        self.assertEqual(by_phone_path["/storage/1234-abcd/Movies/b.MP4"].relative_path, "Movies/b.MP4")
        self.assertEqual(
            adb.excluded_paths_by_root["/sdcard"],
            (
                "/sdcard/Android/data",
                "/sdcard/Android/obb",
                "/sdcard/WhatsApp/Databases",
                "/sdcard/WhatsApp/Backups",
                "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases",
                "/sdcard/Android/media/com.whatsapp/WhatsApp/Backups",
            ),
        )
        self.assertEqual(
            adb.excluded_paths_by_root["/storage/1234-abcd"],
            (
                "/storage/1234-abcd/Android/data",
                "/storage/1234-abcd/Android/obb",
                "/storage/1234-abcd/WhatsApp/Databases",
                "/storage/1234-abcd/WhatsApp/Backups",
                "/storage/1234-abcd/Android/media/com.whatsapp/WhatsApp/Databases",
                "/storage/1234-abcd/Android/media/com.whatsapp/WhatsApp/Backups",
            ),
        )
        self.assertEqual(result.warnings, [])

    def test_whatsapp_databases_and_backups_are_pruned_and_media_remains(self) -> None:
        adb = FakeAdb()
        adb.listings["/sdcard"] = RemoteListing(
            files=[
                RemoteFileStat(
                    "/sdcard/WhatsApp/Media/Images/legacy.jpg", 10, 1
                ),
                RemoteFileStat(
                    "/sdcard/Android/media/com.whatsapp/WhatsApp/Media/Images/new.jpg",
                    20,
                    2,
                ),
                RemoteFileStat(
                    "/sdcard/WhatsApp/Databases/msgstore.db", 30, 3
                ),
                RemoteFileStat(
                    "/sdcard/WhatsApp/Backups/backup.zip", 40, 4
                ),
                RemoteFileStat(
                    "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases/msgstore.db",
                    50,
                    5,
                ),
                RemoteFileStat(
                    "/sdcard/Android/media/com.whatsapp/WhatsApp/Backups/backup.zip",
                    60,
                    6,
                ),
            ],
            symlinks=["/sdcard/WhatsApp/Databases/shortcut.db"],
        )
        source = StorageSource(
            source_id="internal",
            root_path="/sdcard",
            label_en="Internal",
            label_ar="الداخلية",
            kind=SourceKind.INTERNAL_STORAGE,
            volume_root="/sdcard",
        )

        result = scan_sources(adb, "PHONE-1", [source])

        self.assertEqual(
            [item.phone_path for item in result.files],
            [
                "/sdcard/WhatsApp/Media/Images/legacy.jpg",
                "/sdcard/Android/media/com.whatsapp/WhatsApp/Media/Images/new.jpg",
            ],
        )
        self.assertEqual(result.warnings, [])
        self.assertEqual(result.skipped_symlink_count, 0)

    def test_unavailable_folder_is_reported_and_other_sources_continue(self) -> None:
        source_missing = StorageSource(
            source_id="missing",
            root_path="/sdcard/Missing",
            label_en="Missing",
            label_ar="مفقود",
        )
        source_download = StorageSource(
            source_id="download",
            root_path="/sdcard/Download",
            label_en="Download",
            label_ar="التنزيلات",
            volume_root="/sdcard",
        )

        result = scan_sources(
            FakeAdb(), "PHONE-1", [source_missing, source_download]
        )

        self.assertEqual(result.total_files, 1)
        self.assertEqual(result.warnings[0].source_id, "missing")
        self.assertEqual(result.warnings[0].phone_path, "/sdcard/Missing")
        self.assertEqual(result.sources_scanned, ["download"])

    def test_android_data_and_obb_are_pruned_but_android_media_is_scanned(self) -> None:
        adb = FakeAdb()
        adb.directories.add("/sdcard/Android")
        adb.listings["/sdcard/Android"] = RemoteListing(
            files=[
                RemoteFileStat(
                    "/sdcard/Android/media/com.whatsapp/WhatsApp/Media/photo.jpg",
                    50,
                    1710000000,
                )
            ]
        )

        result = scan_sources(adb, "PHONE-1", [custom_source("/sdcard/Android")])

        self.assertEqual(result.total_files, 1)
        self.assertEqual(result.files[0].phone_path,
                         "/sdcard/Android/media/com.whatsapp/WhatsApp/Media/photo.jpg")
        self.assertEqual(
            adb.excluded_paths_by_root["/sdcard/Android"],
            (
                "/sdcard/Android/data",
                "/sdcard/Android/obb",
                "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases",
                "/sdcard/Android/media/com.whatsapp/WhatsApp/Backups",
            ),
        )

    def test_android_app_data_root_is_skipped_silently(self) -> None:
        adb = FakeAdb()
        source = StorageSource(
            source_id="restricted",
            root_path="/sdcard/Android/data/com.example.app",
            label_en="Restricted",
            label_ar="مستبعد",
            volume_root="/sdcard",
        )

        result = scan_sources(adb, "PHONE-1", [source])

        self.assertEqual(result.total_files, 0)
        self.assertEqual(result.warnings, [])
        self.assertNotIn(source.root_path, adb.directory_checks)

    def test_symlinks_are_counted_and_skipped_without_following_targets(self) -> None:
        adb = FakeAdb()
        adb.listings["/sdcard/DCIM"] = RemoteListing(
            symlinks=["/sdcard/DCIM/shortcut.jpg"]
        )
        source = StorageSource(
            source_id="dcim",
            root_path="/sdcard/DCIM",
            label_en="DCIM",
            label_ar="الكاميرا",
            volume_root="/sdcard",
        )

        result = scan_sources(adb, "PHONE-1", [source])

        self.assertEqual(result.total_files, 0)
        self.assertEqual(result.skipped_symlink_count, 1)
        self.assertEqual(result.skipped_symlink_paths, ["/sdcard/DCIM/shortcut.jpg"])
        self.assertEqual(result.warnings[0].phone_path, "/sdcard/DCIM/shortcut.jpg")

    def test_files_outside_selected_root_are_not_included(self) -> None:
        adb = FakeAdb()
        adb.listings["/sdcard/Custom"] = RemoteListing(
            files=[
                RemoteFileStat("/sdcard/Custom/one.bin", 1, 1),
                RemoteFileStat("/sdcard/secret.jpg", 99, 1),
            ]
        )
        source = StorageSource(
            source_id="custom",
            root_path="/sdcard/Custom",
            label_en="Custom",
            label_ar="مخصص",
            kind=SourceKind.CUSTOM,
            volume_root="/sdcard",
        )

        result = scan_sources(adb, "PHONE-1", [source])

        self.assertEqual(
            [item.phone_path for item in result.files],
            ["/sdcard/Custom/one.bin"],
        )
        self.assertEqual(result.warnings[0].phone_path, "/sdcard/secret.jpg")
        self.assertIs(result.files[0].category, MediaCategory.OTHER)


if __name__ == "__main__":
    unittest.main()
