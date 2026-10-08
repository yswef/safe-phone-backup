from __future__ import annotations

import importlib.util
import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from phone_media_vault.app.api import AppApi, safe_folder_name
from phone_media_vault.app.demo import DemoPhone
from phone_media_vault.app.server import make_handler
from phone_media_vault.core.settings import SettingsStore
from phone_media_vault.core.wipe import WIPE_CONFIRMATION_PHRASES
from phone_media_vault.tests._helpers import BackupFixture, FakeProtector


def wait(api: AppApi, snapshot: dict, timeout: float = 30.0) -> dict:
    deadline = time.time() + timeout
    job_id = snapshot["data"]["id"]
    while time.time() < deadline:
        job = api.get_job(job_id)["data"]
        if job["state"] in ("done", "error", "cancelled"):
            return job
        time.sleep(0.05)
    raise AssertionError("job timed out")


class ApiFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.phone = DemoPhone(self.root / "phone")
        patcher = mock.patch(
            "phone_media_vault.core.signer.WindowsDpapiProtector", FakeProtector
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        api_patcher = mock.patch("phone_media_vault.app.api.WindowsDpapiProtector", FakeProtector)
        api_patcher.start()
        self.addCleanup(api_patcher.stop)
        self.api = AppApi(adb=self.phone, writer=self.phone, app_data_dir=self.root / "appdata", demo=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_full_gui_flow(self) -> None:
        info = self.api.app_info()
        self.assertTrue(info["ok"])
        self.assertTrue(info["data"]["demo"])
        self.assertTrue(self.api.setup_key(None)["ok"])  # DPAPI-style key (faked)
        device = self.api.select_device(None)["data"]
        self.assertEqual(device["model"], "Demo Phone X")
        sources = self.api.discover_sources()["data"]
        ids = [s["source_id"] for s in sources]
        self.assertIn("internal:entire", ids)

        error = self.api.add_custom_folder("/sdcard/Android/data/x")
        self.assertFalse(error["ok"])
        self.assertTrue(self.api.add_custom_folder("/sdcard/DCIM/Camera")["ok"])

        scan = wait(self.api, self.api.start_scan(["internal:entire"]))
        self.assertEqual(scan["state"], "done")
        self.assertGreater(scan["result"]["total_files"], 0)

        destination = str(self.root / "backup")
        backup = wait(self.api, self.api.start_backup(destination, {"verify_after": True}))
        self.assertEqual(backup["state"], "done", backup["error"])
        self.assertTrue(backup["result"]["fully_verified"])
        self.assertTrue(backup["result"]["verification"]["complete"])
        self.assertTrue(Path(backup["result"]["report_path"]).is_file())

        verify = wait(self.api, self.api.start_verify(destination))
        self.assertTrue(verify["result"]["complete"])

        restore = wait(self.api, self.api.start_restore(destination, "folder", "/sdcard/Restored", "skip"))
        self.assertEqual(restore["result"]["restored"], scan["result"]["total_files"])

        self.assertFalse(self.api.execute_wipe(WIPE_CONFIRMATION_PHRASES[0])["ok"])  # no plan yet
        plan = wait(self.api, self.api.start_wipe_plan(destination))
        self.assertEqual(plan["result"]["eligible_count"], scan["result"]["total_files"])
        self.assertFalse(self.api.execute_wipe("wrong")["ok"])
        wiped = wait(self.api, self.api.execute_wipe(WIPE_CONFIRMATION_PHRASES[0]))
        self.assertEqual(wiped["result"]["deleted_count"], scan["result"]["total_files"])

        kinds = [h["kind"] for h in self.api.get_history()["data"]]
        self.assertEqual(kinds[:4], ["wipe", "restore", "verify", "backup"])

    def test_backup_requires_scan_and_device(self) -> None:
        self.assertFalse(self.api.start_backup("x")["ok"])
        self.api.select_device(None)
        self.assertFalse(self.api.start_backup("x")["ok"])

    def test_settings_roundtrip_and_validation(self) -> None:
        saved = self.api.save_settings({"max_retries": 99, "restore_conflict_policy": "bogus", "unknown": 1})["data"]
        self.assertEqual(saved["max_retries"], 10)
        self.assertEqual(saved["restore_conflict_policy"], "skip")
        self.assertEqual(SettingsStore(self.root / "appdata").load().max_retries, 10)

    def test_safe_folder_name(self) -> None:
        self.assertEqual(safe_folder_name('Pixel 8: "Pro"/x'), "Pixel 8_ _Pro_x")
        self.assertEqual(safe_folder_name("..."), "phone")


class ServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        phone = DemoPhone(root / "phone")
        self.api = AppApi(adb=phone, writer=phone, app_data_dir=root / "appdata", demo=True)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.api, "secret-token"))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._tmp.cleanup()

    def _post(self, method: str, args: list, token: str | None = "secret-token"):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["X-PMV-Token"] = token
        request = urllib.request.Request(
            f"{self.base}/api/{method}", data=json.dumps({"args": args}).encode(), headers=headers
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read())

    def test_index_contains_token_and_static_files_served(self) -> None:
        with urllib.request.urlopen(self.base + "/", timeout=10) as response:
            body = response.read().decode()
        self.assertIn('window.PMV_TOKEN = "secret-token"', body)
        with urllib.request.urlopen(self.base + "/js/app.js", timeout=10) as response:
            self.assertEqual(response.status, 200)

    def test_api_requires_token(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self._post("app_info", [], token="wrong")
        self.assertEqual(caught.exception.code, 403)
        self.assertTrue(self._post("app_info", [])["ok"])

    def test_private_methods_and_traversal_are_blocked(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self._post("_adb", [])
        self.assertEqual(caught.exception.code, 404)
        with self.assertRaises(urllib.error.HTTPError):
            urllib.request.urlopen(self.base + "/../../etc/passwd", timeout=10)


@unittest.skipUnless(importlib.util.find_spec("pyzipper"), "pyzipper not installed")
class ArchiveTests(unittest.TestCase):
    def test_encrypted_export_roundtrip(self) -> None:
        import pyzipper

        from phone_media_vault.core.archive import ArchiveError, export_encrypted_archive

        fx = BackupFixture()
        try:
            result = fx.make_backup()
            target = fx.root / "export.zip"
            with self.assertRaises(ArchiveError):
                export_encrypted_archive(fx.backup_dir, target, "short")
            exported = export_encrypted_archive(fx.backup_dir, target, "long-password", trusted_public_key_bytes=fx.trusted_key)
            self.assertEqual(exported.files_archived, result.files_total)
            with pyzipper.AESZipFile(target) as archive:
                archive.setpassword(b"long-password")
                self.assertIn("manifest.json", archive.namelist())
                with self.assertRaises(RuntimeError):
                    archive.setpassword(b"wrong-password")
                    archive.read("manifest.json")
            with self.assertRaises(ArchiveError):
                export_encrypted_archive(fx.backup_dir, target, "long-password")  # exists
        finally:
            fx.cleanup()


if __name__ == "__main__":
    unittest.main()
