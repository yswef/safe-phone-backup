"""JavaScript-facing API shared by the pywebview window and the browser mode.

Every public method returns ``{"ok": true, "data": ...}`` or
``{"ok": false, "error": "<Arabic message>", "details": "..."}``. Long tasks
(scan, backup, verify, restore, wipe, export) run as background jobs that the
UI polls with :meth:`AppApi.get_job`.
"""

from __future__ import annotations

import functools
import os
import re
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .. import __version__
from ..core.adb_manager import AdbError, AdbManager
from ..core.adb_writer import AdbWriter
from ..core.archive import export_encrypted_archive
from ..core.backup_engine import BackupEngine
from ..core.models import ScanResult, SourceKind, StorageSource
from ..core.report import human_size, write_verification_report
from ..core.restore import RestoreEngine
from ..core.scanner import custom_source, discover_sources, scan_sources
from ..core.settings import SettingsStore
from ..core.signer import (
    KeyPasswordRequiredError,
    ManifestSigner,
    PrivateKeyStore,
    WindowsDpapiProtector,
)
from ..core.verifier import verify_backup
from ..core.wipe import WIPE_CONFIRMATION_PHRASES, SafeWipe, WipePlan
from .jobs import Job, JobManager, to_jsonable

_UNSAFE_NAME = re.compile(r'[<>:"/\\|?*\x00-\x1f]+')


def _api(method: Callable[..., Any]) -> Callable[..., dict[str, Any]]:
    @functools.wraps(method)
    def wrapper(self: "AppApi", *args: Any, **kwargs: Any) -> dict[str, Any]:
        try:
            return {"ok": True, "data": to_jsonable(method(self, *args, **kwargs))}
        except Exception as exc:  # noqa: BLE001 - all errors are shown in the UI
            return {
                "ok": False,
                "error": getattr(exc, "message_ar", None) or str(exc) or exc.__class__.__name__,
                "details": getattr(exc, "details", None),
            }

    wrapper.__pmv_api__ = True  # type: ignore[attr-defined]
    return wrapper


def safe_folder_name(text: str) -> str:
    cleaned = _UNSAFE_NAME.sub("_", text).strip(" .")
    return cleaned[:80] or "phone"


class AppApi:
    """Bridge object; attributes starting with ``_`` are hidden from pywebview."""

    def __init__(
        self,
        *,
        adb: Any | None = None,
        writer: Any | None = None,
        app_data_dir: str | os.PathLike[str] | None = None,
        demo: bool = False,
    ) -> None:
        self._demo = demo
        self._adb_instance = adb
        self._writer_instance = writer
        self._adb_error: str | None = None
        self._app_data = Path(app_data_dir) if app_data_dir else None
        self._settings = SettingsStore(self._app_data)
        key_path = (self._app_data / "keys" / "ed25519-private.key") if self._app_data else None
        self._key_store = PrivateKeyStore(key_path)
        self._signer = ManifestSigner(self._key_store)
        self._signing_password: str | None = None
        self._jobs = JobManager()
        self._serial: str | None = None
        self._device = None
        self._sources: dict[str, StorageSource] = {}
        self._last_scan: ScanResult | None = None
        self._wipe_plan: WipePlan | None = None
        self._window = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------ internals
    def _adb(self):
        if self._adb_instance is None:
            self._adb_instance = AdbManager()
        return self._adb_instance

    def _writer(self):
        if self._writer_instance is None:
            adb = self._adb()
            self._writer_instance = adb if self._demo else AdbWriter(adb)
        return self._writer_instance

    def _require_device(self) -> str:
        if not self._serial:
            raise AdbError("اختر هاتفاً متصلاً أولاً من صفحة الجهاز.")
        return self._serial

    def _trusted_key(self) -> bytes | None:
        path = self._signer.trusted_public_key_path
        try:
            return path.read_bytes() if path.is_file() else None
        except OSError:
            return None

    def _key_ready(self) -> None:
        try:
            self._signer.public_key_bytes(self._signing_password)
        except KeyPasswordRequiredError as exc:
            raise KeyPasswordRequiredError() from exc

    # ------------------------------------------------------------ app/key
    @_api
    def app_info(self) -> dict[str, Any]:
        adb_path = None
        try:
            adb_path = getattr(self._adb(), "adb_path", None)
            self._adb_error = None
        except AdbError as exc:
            self._adb_error = exc.message_ar
        return {
            "version": __version__,
            "demo": self._demo,
            "platform": sys.platform,
            "adb_path": adb_path,
            "adb_error": self._adb_error,
            "can_choose_folder": self._window is not None,
            "wipe_phrases": list(WIPE_CONFIRMATION_PHRASES),
            "key": self._key_status(),
        }

    def _key_status(self) -> dict[str, Any]:
        mode = self._key_store.protection_mode
        unlocked = False
        if mode == "dpapi":
            unlocked = True
        elif mode == "password":
            unlocked = self._signing_password is not None
        return {
            "exists": mode is not None,
            "mode": mode,
            "dpapi_available": WindowsDpapiProtector().available(),
            "unlocked": unlocked,
            "key_path": str(self._key_store.key_path),
        }

    @_api
    def key_status(self) -> dict[str, Any]:
        return self._key_status()

    @_api
    def setup_key(self, password: str | None = None) -> dict[str, Any]:
        """Create the signing key (first run) or unlock a password-protected key."""

        password = password or None
        if self._key_store.protection_mode is None and password is None and not WindowsDpapiProtector().available():
            raise ValueError("عيّن كلمة مرور لحماية مفتاح التوقيع (DPAPI غير متاح على هذا النظام).")
        if password is not None and self._key_store.protection_mode is None and len(password) < 8:
            raise ValueError("كلمة مرور المفتاح يجب أن تكون 8 أحرف على الأقل.")
        self._signer.public_key_bytes(password)
        self._signing_password = password
        return self._key_status()

    # ------------------------------------------------------------ devices
    @_api
    def list_devices(self) -> list[dict[str, Any]]:
        return [
            {**to_jsonable(d), "status_ar": d.status_ar, "authorized": d.is_authorized}
            for d in self._adb().list_devices()
        ]

    @_api
    def select_device(self, serial: str | None = None) -> dict[str, Any]:
        device = self._adb().get_device_info(serial or None)
        self._serial = device.serial
        self._device = device
        self._sources = {}
        self._last_scan = None
        self._wipe_plan = None
        return {**to_jsonable(device), "status_ar": device.status_ar, "suggested_destination": self._suggest_destination()}

    def _suggest_destination(self) -> str:
        settings = self._settings.load()
        base = settings.default_destination or str(Path.home() / "PhoneMediaVault")
        if self._device is None:
            return base
        name = safe_folder_name(f"{self._device.model}_{self._device.serial[-6:]}")
        return str(Path(base) / name)

    @_api
    def current_device(self) -> dict[str, Any] | None:
        if self._device is None:
            return None
        return {**to_jsonable(self._device), "status_ar": self._device.status_ar,
                "suggested_destination": self._suggest_destination()}

    # ------------------------------------------------------------ sources/scan
    @_api
    def discover_sources(self) -> list[dict[str, Any]]:
        serial = self._require_device()
        sources = discover_sources(self._adb(), serial)
        settings = self._settings.load()
        for path in settings.custom_folders:
            try:
                source = custom_source(path)
                sources.append(source)
            except ValueError:
                continue
        self._sources = {s.source_id: s for s in sources}
        selected = set(settings.last_selected_sources)
        return [
            {
                "source_id": s.source_id,
                "root_path": s.root_path,
                "label_ar": s.label_ar,
                "label_en": s.label_en,
                "kind": s.kind.value,
                "removable": s.removable,
                "selected": s.source_id in selected,
            }
            for s in sources
        ]

    @_api
    def add_custom_folder(self, phone_path: str) -> dict[str, Any]:
        source = custom_source(phone_path)
        self._sources[source.source_id] = source
        settings = self._settings.load()
        if source.root_path not in settings.custom_folders:
            settings.custom_folders.append(source.root_path)
            self._settings.save(settings)
        return {"source_id": source.source_id, "root_path": source.root_path,
                "label_ar": source.label_ar, "kind": source.kind.value, "removable": False, "selected": True}

    @_api
    def remove_custom_folder(self, phone_path: str) -> bool:
        settings = self._settings.load()
        settings.custom_folders = [p for p in settings.custom_folders if p != phone_path]
        self._settings.save(settings)
        self._sources.pop(f"custom:{phone_path}", None)
        return True

    @_api
    def start_scan(self, source_ids: list[str]) -> dict[str, Any]:
        serial = self._require_device()
        sources = [self._sources[s] for s in source_ids if s in self._sources]
        if not sources:
            raise ValueError("اختر مصدراً واحداً على الأقل للفحص.")
        self._settings.update({"last_selected_sources": [s.source_id for s in sources]})

        def work(job: Job) -> dict[str, Any]:
            job.set_progress({"message": "جارٍ فحص الهاتف…", "sources": len(sources)})
            result = scan_sources(self._adb(), serial, sources)
            self._last_scan = result
            return self._scan_summary(result)

        return self._jobs.start("scan", work).snapshot()

    @staticmethod
    def _scan_summary(result: ScanResult) -> dict[str, Any]:
        return {
            "total_files": result.total_files,
            "total_bytes": result.total_bytes,
            "total_human": human_size(result.total_bytes),
            "photo_count": result.photo_count,
            "photo_human": human_size(result.photo_bytes),
            "video_count": result.video_count,
            "video_human": human_size(result.video_bytes),
            "other_count": result.other_count,
            "other_human": human_size(result.other_bytes),
            "symlinks_skipped": result.skipped_symlink_count,
            "warnings": [
                {"message_ar": w.message_ar, "phone_path": w.phone_path, "detail": w.detail}
                for w in result.warnings[:200]
            ],
            "warnings_count": len(result.warnings),
        }

    # ------------------------------------------------------------ backup
    @_api
    def start_backup(self, destination: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
        serial = self._require_device()
        if self._last_scan is None or not self._last_scan.files:
            raise ValueError("افحص الهاتف أولاً واختر ملفات للنسخ.")
        if not destination:
            raise ValueError("حدد مجلد الوجهة على الكمبيوتر.")
        self._key_ready()
        options = options or {}
        settings = self._settings.load()
        hash_serial = bool(options.get("hash_serial", settings.hash_serial))
        verify_after = bool(options.get("verify_after", settings.verify_after_backup))
        destination_path = Path(destination).expanduser()
        scan = self._last_scan
        device = self._device
        engine = BackupEngine(self._adb(), self._signer, app_version=__version__,
                              max_retries=settings.max_retries)

        def work(job: Job) -> dict[str, Any]:
            result = engine.backup(
                serial, device, scan, destination_path,
                hash_serial=hash_serial,
                signing_password=self._signing_password,
                cancel_event=job.cancel_event,
                pause_event=job.pause_event,
                progress_callback=lambda p: job.set_progress({"phase": "backup", **to_jsonable(p)}),
            )
            summary: dict[str, Any] = {
                "backup_directory": str(result.backup_directory),
                "files_total": result.files_total,
                "verified_count": result.verified_count,
                "skipped_count": result.skipped_count,
                "failed_count": result.failed_count,
                "verified_human": human_size(result.verified_bytes),
                "failed_files": result.failed_files[:200],
                "fully_verified": result.fully_verified,
                "cancelled": result.cancelled,
                "interrupted": result.interrupted,
                "scan_warnings": len(result.scan_warnings),
            }
            if verify_after and not result.cancelled:
                job.set_progress({"phase": "verify", "message": "جارٍ التحقق من النسخة…"})
                report = verify_backup(
                    result.backup_directory,
                    trusted_public_key_bytes=self._trusted_key(),
                    cancel_event=job.cancel_event,
                    progress_callback=lambda p: job.set_progress({"phase": "verify", **to_jsonable(p)}),
                )
                summary["verification"] = report.to_dict()
                summary["report_path"] = str(write_verification_report(report, app_version=__version__))
            self._settings.add_history(
                "backup",
                backup_directory=str(result.backup_directory),
                device=getattr(device, "model", ""),
                files=result.files_total,
                verified=result.verified_count,
                failed=result.failed_count,
                fully_verified=result.fully_verified,
            )
            return summary

        return self._jobs.start("backup", work).snapshot()

    # ------------------------------------------------------------ verify
    @_api
    def start_verify(self, backup_directory: str) -> dict[str, Any]:
        path = Path(backup_directory).expanduser()
        if not path.is_dir():
            raise ValueError("مجلد النسخة غير موجود.")

        def work(job: Job) -> dict[str, Any]:
            report = verify_backup(
                path,
                trusted_public_key_bytes=self._trusted_key(),
                cancel_event=job.cancel_event,
                progress_callback=job.set_progress,
            )
            data = report.to_dict()
            if report.manifest_present:
                try:
                    data["report_path"] = str(write_verification_report(report, app_version=__version__))
                except OSError:
                    data["report_path"] = None
            self._settings.add_history("verify", backup_directory=str(path), intact=report.intact,
                                       complete=report.complete, damaged=len(report.damaged_checks))
            return data

        return self._jobs.start("verify", work).snapshot()

    # ------------------------------------------------------------ restore
    @_api
    def start_restore(self, backup_directory: str, mode: str = "folder", target_root: str | None = None,
                      conflict_policy: str | None = None) -> dict[str, Any]:
        serial = self._require_device()
        settings = self._settings.load()
        engine = RestoreEngine(self._writer(), trusted_public_key_bytes=self._trusted_key())
        plan = engine.plan(
            Path(backup_directory).expanduser(), mode=mode,
            target_root=target_root or settings.restore_target_folder,
        )
        if not plan.items:
            raise ValueError("لا توجد ملفات موثقة قابلة للاستعادة في هذه النسخة.")
        policy = conflict_policy or settings.restore_conflict_policy

        def work(job: Job) -> dict[str, Any]:
            result = engine.restore(
                serial, plan, conflict_policy=policy, cancel_event=job.cancel_event,
                progress_callback=job.set_progress, media_scan=settings.media_scan_after_changes,
            )
            data = result.to_dict()
            data["outcomes"] = [o for o in data["outcomes"] if o["status"] not in ("restored",)][:300]
            data["planned"] = len(plan.items)
            data["skipped_entries"] = plan.skipped_entries[:100]
            self._settings.add_history("restore", backup_directory=str(plan.backup_directory),
                                       restored=result.restored_count, failed=result.failed_count)
            return data

        return self._jobs.start("restore", work).snapshot()

    # ------------------------------------------------------------ safe wipe
    @_api
    def start_wipe_plan(self, backup_directory: str) -> dict[str, Any]:
        serial = self._require_device()
        wiper = SafeWipe(self._writer(), trusted_public_key_bytes=self._trusted_key())
        self._wipe_plan = None

        def work(job: Job) -> dict[str, Any]:
            plan = wiper.plan(serial, Path(backup_directory).expanduser(), cancel_event=job.cancel_event,
                              progress_callback=job.set_progress)
            self._wipe_plan = plan
            data = plan.to_dict()
            data["eligible"] = data["eligible"][:500]
            data["rejected"] = data["rejected"][:500]
            data["eligible_human"] = human_size(plan.eligible_bytes)
            return data

        return self._jobs.start("wipe_plan", work).snapshot()

    @_api
    def execute_wipe(self, confirmation: str) -> dict[str, Any]:
        plan = self._wipe_plan
        if plan is None or plan.serial != self._serial:
            raise ValueError("افحص الملفات القابلة للحذف أولاً.")
        if not plan.eligible:
            raise ValueError("لا توجد ملفات مؤكدة النسخ لحذفها.")
        if confirmation.strip() not in WIPE_CONFIRMATION_PHRASES:
            raise ValueError("عبارة التأكيد غير صحيحة؛ لم يُحذف أي ملف.")
        wiper = SafeWipe(self._writer(), trusted_public_key_bytes=self._trusted_key())
        media_scan = self._settings.load().media_scan_after_changes

        def work(job: Job) -> dict[str, Any]:
            result = wiper.execute(plan, confirmation, cancel_event=job.cancel_event,
                                   progress_callback=job.set_progress, media_scan=media_scan)
            self._wipe_plan = None
            data = result.to_dict()
            data["freed_human"] = human_size(result.freed_bytes)
            self._settings.add_history("wipe", backup_directory=str(plan.backup_directory),
                                       deleted=len(result.deleted), freed_bytes=result.freed_bytes)
            return data

        return self._jobs.start("wipe", work).snapshot()

    # ------------------------------------------------------------ export
    @_api
    def start_export(self, backup_directory: str, archive_path: str, password: str) -> dict[str, Any]:
        source = Path(backup_directory).expanduser()
        target = Path(archive_path).expanduser()
        if target.suffix.lower() != ".zip":
            target = target.with_suffix(".zip")

        def work(job: Job) -> dict[str, Any]:
            result = export_encrypted_archive(
                source, target, password, trusted_public_key_bytes=self._trusted_key(),
                cancel_event=job.cancel_event, progress_callback=job.set_progress,
            )
            return {"archive_path": str(result.archive_path), "files": result.files_archived,
                    "size_human": human_size(result.bytes_archived)}

        return self._jobs.start("export", work).snapshot()

    # ------------------------------------------------------------ jobs
    @_api
    def get_job(self, job_id: str) -> dict[str, Any]:
        job = self._jobs.get(job_id)
        if job is None:
            raise ValueError("العملية غير موجودة.")
        return job.snapshot()

    @_api
    def active_job(self) -> dict[str, Any] | None:
        job = self._jobs.active()
        return job.snapshot() if job else None

    @_api
    def pause_job(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if job:
            job.pause_event.set()
        return bool(job)

    @_api
    def resume_job(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if job:
            job.pause_event.clear()
        return bool(job)

    @_api
    def cancel_job(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if job:
            job.cancel_event.set()
            job.pause_event.clear()
        return bool(job)

    # ------------------------------------------------------------ settings/history
    @_api
    def get_settings(self) -> dict[str, Any]:
        return to_jsonable(self._settings.load())

    @_api
    def save_settings(self, changes: dict[str, Any]) -> dict[str, Any]:
        return to_jsonable(self._settings.update(changes or {}))

    @_api
    def get_history(self) -> list[dict[str, Any]]:
        return self._settings.history()

    # ------------------------------------------------------------ desktop helpers
    @_api
    def choose_folder(self) -> str | None:
        if self._window is None:
            raise ValueError("اختيار المجلد متاح في نافذة التطبيق فقط؛ اكتب المسار يدوياً.")
        import webview  # type: ignore

        dialog = getattr(getattr(webview, "FileDialog", None), "FOLDER", None)
        if dialog is None:
            dialog = webview.FOLDER_DIALOG
        selection = self._window.create_file_dialog(dialog)
        if not selection:
            return None
        return selection[0] if isinstance(selection, (list, tuple)) else str(selection)

    @_api
    def open_path(self, path: str) -> bool:
        target = Path(path).expanduser()
        if not target.exists():
            raise ValueError("المسار غير موجود.")
        if os.name == "nt":
            os.startfile(str(target))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(target)])
        else:
            subprocess.Popen(["xdg-open", str(target)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True

    @_api
    def default_archive_name(self, backup_directory: str) -> str:
        source = Path(backup_directory).expanduser()
        stamp = datetime.now().strftime("%Y%m%d-%H%M")
        return str(source.parent / f"{source.name}-{stamp}.zip")
