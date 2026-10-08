from __future__ import annotations

import json
import os
import unittest

from phone_media_vault.core.adb_writer import PhoneWriteRefused, validate_writable_phone_path
from phone_media_vault.core.restore import RestoreEngine, RestoreError
from phone_media_vault.core.wipe import WIPE_CONFIRMATION_PHRASES, SafeWipe, WipeError
from phone_media_vault.tests._helpers import BackupFixture

PHRASE = WIPE_CONFIRMATION_PHRASES[1]


class WritablePathTests(unittest.TestCase):
    def test_protected_and_private_paths_are_refused(self) -> None:
        for bad in (
            "/data/data/app/file", "/sdcard", "/sdcard/Android/data/x/y", "/sdcard/Android/OBB/x",
            "/sdcard/WhatsApp/Databases/msgstore.db", "/storage/emulated/0/WhatsApp/Backups/x",
            "/sdcard/../data/x", "relative/path",
        ):
            with self.assertRaises((PhoneWriteRefused, ValueError), msg=bad):
                validate_writable_phone_path(bad)
        self.assertEqual(validate_writable_phone_path("/sdcard/DCIM/a.jpg"), "/sdcard/DCIM/a.jpg")
        self.assertEqual(validate_writable_phone_path("/storage/1A2B-3C4D/x.jpg"), "/storage/1A2B-3C4D/x.jpg")


class RestoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = BackupFixture()
        self.result = self.fx.make_backup()
        self.engine = RestoreEngine(self.fx.phone, trusted_public_key_bytes=self.fx.trusted_key)

    def tearDown(self) -> None:
        self.fx.cleanup()

    def test_restore_to_folder_then_idempotent(self) -> None:
        plan = self.engine.plan(self.fx.backup_dir, mode="folder", target_root="/sdcard/Restored")
        self.assertEqual(len(plan.items), self.result.files_total)
        first = self.engine.restore(self.fx.serial, plan)
        self.assertEqual(first.restored_count, self.result.files_total)
        self.assertEqual(first.failed_count, 0)
        sample = plan.items[0]
        local = self.fx.phone.local(sample.target_phone_path)
        self.assertEqual(local.read_bytes(), sample.local_path.read_bytes())
        self.assertEqual(int(local.stat().st_mtime), sample.modified_time)
        second = self.engine.restore(self.fx.serial, plan)
        self.assertEqual(second.already_present_count, self.result.files_total)
        # No leftover temporary files on the phone.
        leftovers = [p for p in self.fx.phone.root.rglob("*.part")]
        self.assertEqual(leftovers, [])

    def test_restore_original_recreates_deleted_file_and_never_overwrites(self) -> None:
        plan = self.engine.plan(self.fx.backup_dir, mode="original")
        deleted = self.fx.phone.local(plan.items[0].original_phone_path)
        deleted.unlink()
        changed = self.fx.phone.local(plan.items[1].original_phone_path)
        changed.write_bytes(b"user edited this file")

        result = self.engine.restore(self.fx.serial, plan, conflict_policy="skip")
        self.assertEqual(result.restored_count, 1)
        self.assertEqual(result.conflict_count, 1)
        self.assertTrue(deleted.is_file())
        self.assertEqual(changed.read_bytes(), b"user edited this file")

        renamed = self.engine.restore(self.fx.serial, plan, conflict_policy="rename")
        outcome = next(o for o in renamed.outcomes if o.status == "renamed")
        self.assertIn("(restored 1)", outcome.target_phone_path)
        self.assertEqual(changed.read_bytes(), b"user edited this file")

    def test_damaged_local_copy_is_not_restored(self) -> None:
        plan = self.engine.plan(self.fx.backup_dir, mode="folder")
        item = plan.items[0]
        data = bytearray(item.local_path.read_bytes())
        data[0] ^= 1
        item.local_path.write_bytes(bytes(data))
        result = self.engine.restore(self.fx.serial, plan)
        self.assertEqual(result.count("local_damaged"), 1)
        self.assertFalse(self.fx.phone.path_exists(self.fx.serial, item.target_phone_path))

    def test_invalid_signature_blocks_restore(self) -> None:
        manifest = self.fx.backup_dir / "manifest.json"
        manifest.write_text(manifest.read_text().replace('"verified"', '"verified" ', 1))
        with self.assertRaises(RestoreError):
            self.engine.plan(self.fx.backup_dir)

    def test_selection_limits_plan(self) -> None:
        wanted = self.result.manifest["files"][0]["original_phone_path"]
        plan = self.engine.plan(self.fx.backup_dir, selected_phone_paths=[wanted])
        self.assertEqual([i.original_phone_path for i in plan.items], [wanted])


class SafeWipeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = BackupFixture()
        self.result = self.fx.make_backup()
        self.wiper = SafeWipe(self.fx.phone, trusted_public_key_bytes=self.fx.trusted_key)

    def tearDown(self) -> None:
        self.fx.cleanup()

    def test_wipe_deletes_only_verified_unchanged_files(self) -> None:
        files = self.result.manifest["files"]
        changed = self.fx.phone.local(files[0]["original_phone_path"])
        os.utime(changed, (1, 1))
        damaged_local = self.fx.backup_dir / files[1]["relative_path"]
        damaged_local.write_bytes(b"corrupted" + damaged_local.read_bytes()[9:])

        plan = self.wiper.plan(self.fx.serial, self.fx.backup_dir)
        self.assertEqual(len(plan.eligible), len(files) - 2)
        rejected = {r.phone_path for r in plan.rejected}
        self.assertEqual(rejected, {files[0]["original_phone_path"], files[1]["original_phone_path"]})

        with self.assertRaises(WipeError):
            self.wiper.execute(plan, "yes")
        result = self.wiper.execute(plan, PHRASE)
        self.assertEqual(len(result.deleted), len(files) - 2)
        self.assertTrue(changed.is_file())
        self.assertTrue(self.fx.phone.local(files[1]["original_phone_path"]).is_file())
        # Protected folders that were never backed up are untouched.
        self.assertTrue(any(self.fx.phone.local("/sdcard/WhatsApp/Databases").iterdir()))
        log = (self.fx.backup_dir / "wipe_log.txt").read_text().splitlines()
        self.assertEqual(sum(json.loads(l)["event"] == "file_deleted" for l in log), len(result.deleted))

    def test_file_changed_after_plan_is_skipped(self) -> None:
        plan = self.wiper.plan(self.fx.serial, self.fx.backup_dir)
        victim = self.fx.phone.local(plan.eligible[0].phone_path)
        victim.write_bytes(b"new content after planning")
        result = self.wiper.execute(plan, PHRASE)
        self.assertEqual(len(result.skipped), 1)
        self.assertTrue(victim.is_file())

    def test_other_phone_is_refused(self) -> None:
        with self.assertRaises(WipeError):
            self.wiper.plan("SOME-OTHER-PHONE", self.fx.backup_dir)

    def test_untrusted_key_is_refused(self) -> None:
        with self.assertRaises(WipeError):
            SafeWipe(self.fx.phone, trusted_public_key_bytes=b"x").plan(self.fx.serial, self.fx.backup_dir)


class SafeWipeWithoutPhoneHashTests(unittest.TestCase):
    def test_phone_without_sha256sum_is_never_wiped(self) -> None:
        fx = BackupFixture(sha256_available=False)
        try:
            fx.make_backup()
            plan = SafeWipe(fx.phone).plan(fx.serial, fx.backup_dir)
            self.assertEqual(plan.eligible, [])
            self.assertTrue(all("sha256sum" in r.reason_ar for r in plan.rejected))
        finally:
            fx.cleanup()


if __name__ == "__main__":
    unittest.main()
