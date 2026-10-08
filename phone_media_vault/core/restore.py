"""Verified restore from a signed backup back to an Android phone.

Safety rules:

* the backup manifest signature must be valid (and trusted when a local trust
  anchor is supplied) before anything is written to the phone;
* each local file is re-hashed against the signed manifest before pushing, so a
  damaged backup file is never restored;
* existing phone files are never overwritten: identical files are reported as
  already present, different files are skipped or restored under a new name;
* every push lands in a temporary name, is verified on the phone (SHA-256, or
  size when the phone lacks ``sha256sum``), and only then moved with ``mv -n``.
"""

from __future__ import annotations

import hmac
import json
import os
import posixpath
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Protocol

from .adb_manager import AdbCommandError, AdbError, AdbManager
from .adb_writer import PhoneWriteRefused, shared_volume_root, validate_writable_phone_path
from .backup_engine import sha256_file
from .verifier import load_signed_manifest, safe_manifest_path

RESTORE_LOG_FILE = "restore_log.txt"
DEFAULT_RESTORE_FOLDER = "/sdcard/Restored"


class RestoreError(RuntimeError):
    def __init__(self, message_ar: str, details: str | None = None) -> None:
        super().__init__(message_ar)
        self.message_ar = message_ar
        self.details = details

    def __str__(self) -> str:
        return f"{self.message_ar}\n{self.details}" if self.details else self.message_ar


class RestoreWriter(Protocol):
    def remote_stat(self, serial: str, phone_path: str) -> tuple[int, int] | None: ...
    def remote_sha256(self, serial: str, phone_path: str) -> str | None: ...
    def path_exists(self, serial: str, phone_path: str) -> bool: ...
    def make_directories(self, serial: str, phone_dir: str) -> None: ...
    def push_file(self, serial: str, local_path, phone_path: str, *, timeout: float | None = None) -> None: ...
    def rename(self, serial: str, source: str, destination: str) -> None: ...
    def set_modified_time(self, serial: str, phone_path: str, epoch_seconds: int) -> bool: ...
    def delete_file(self, serial: str, phone_path: str) -> None: ...
    def media_scan(self, serial: str, phone_path: str) -> None: ...


@dataclass(frozen=True)
class RestoreItem:
    original_phone_path: str
    target_phone_path: str
    local_path: Path
    relative_path: str
    size: int
    sha256: str
    modified_time: int


@dataclass
class RestorePlan:
    backup_directory: Path
    items: list[RestoreItem] = field(default_factory=list)
    skipped_entries: list[dict[str, str]] = field(default_factory=list)
    mode: str = "original"
    target_root: str | None = None

    @property
    def total_bytes(self) -> int:
        return sum(item.size for item in self.items)


@dataclass(frozen=True)
class RestoreProgress:
    files_total: int
    files_done: int
    bytes_total: int
    bytes_done: int
    current_phone_path: str | None
    speed_bytes_per_second: float
    eta_seconds: float | None


@dataclass
class RestoreOutcome:
    original_phone_path: str
    target_phone_path: str
    status: str  # restored | renamed | already_present | conflict_skipped | failed | local_damaged
    detail: str | None = None


@dataclass
class RestoreResult:
    outcomes: list[RestoreOutcome] = field(default_factory=list)
    cancelled: bool = False
    interrupted: bool = False

    def count(self, *statuses: str) -> int:
        return sum(outcome.status in statuses for outcome in self.outcomes)

    @property
    def restored_count(self) -> int:
        return self.count("restored", "renamed")

    @property
    def already_present_count(self) -> int:
        return self.count("already_present")

    @property
    def failed_count(self) -> int:
        return self.count("failed", "local_damaged")

    @property
    def conflict_count(self) -> int:
        return self.count("conflict_skipped")

    def to_dict(self) -> dict[str, object]:
        return {
            "restored": self.restored_count,
            "already_present": self.already_present_count,
            "failed": self.failed_count,
            "conflicts": self.conflict_count,
            "cancelled": self.cancelled,
            "interrupted": self.interrupted,
            "outcomes": [outcome.__dict__ for outcome in self.outcomes],
        }


def _relative_to_volume(phone_path: str) -> str:
    volume = shared_volume_root(phone_path)
    if volume is None:
        raise PhoneWriteRefused("المسار الأصلي ليس ضمن التخزين المشترك.")
    return posixpath.relpath(phone_path, volume)


def _renamed_candidate(path: str, index: int) -> str:
    directory, name = posixpath.split(path)
    stem, extension = posixpath.splitext(name)
    return posixpath.join(directory, f"{stem} (restored {index}){extension}")


class RestoreEngine:
    def __init__(
        self,
        writer: RestoreWriter,
        *,
        trusted_public_key_bytes: bytes | None = None,
        push_timeout: float = 900.0,
    ) -> None:
        self.writer = writer
        self.trusted_public_key_bytes = trusted_public_key_bytes
        self.push_timeout = push_timeout

    # ------------------------------------------------------------------ plan
    def plan(
        self,
        backup_directory: str | os.PathLike[str],
        *,
        mode: str = "original",
        target_root: str = DEFAULT_RESTORE_FOLDER,
        selected_phone_paths: Iterable[str] | None = None,
    ) -> RestorePlan:
        if mode not in {"original", "folder"}:
            raise ValueError("وضع الاستعادة غير معروف.")
        backup_dir = Path(backup_directory).resolve()
        try:
            manifest, valid, trusted = load_signed_manifest(
                backup_dir, trusted_public_key_bytes=self.trusted_public_key_bytes
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise RestoreError("تعذّر قراءة manifest النسخة الاحتياطية.", str(exc)) from exc
        if not valid:
            raise RestoreError("توقيع النسخة غير صالح؛ أُلغيت الاستعادة حفاظاً على سلامة الهاتف.")
        if trusted is False:
            raise RestoreError("النسخة موقعة بمفتاح غير موثوق على هذا الكمبيوتر.")

        normalized_root: str | None = None
        if mode == "folder":
            normalized_root = validate_writable_phone_path(target_root)

        selection = (
            {AdbManager.validate_phone_path(p) for p in selected_phone_paths}
            if selected_phone_paths is not None
            else None
        )
        plan = RestorePlan(backup_directory=backup_dir, mode=mode, target_root=normalized_root)
        entries = manifest.get("files") if isinstance(manifest.get("files"), list) else []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            phone_path = entry.get("original_phone_path")
            if not isinstance(phone_path, str):
                continue
            if selection is not None and phone_path not in selection:
                continue
            if entry.get("status") != "verified":
                plan.skipped_entries.append({"phone_path": phone_path, "reason": "لم يُنسخ في هذه النسخة."})
                continue
            try:
                original = AdbManager.validate_phone_path(phone_path)
                local = safe_manifest_path(backup_dir, entry.get("relative_path"))
                if mode == "original":
                    target = validate_writable_phone_path(original)
                else:
                    assert normalized_root is not None
                    target = validate_writable_phone_path(
                        posixpath.join(normalized_root, _relative_to_volume(original))
                    )
                size = entry["size"]
                sha = entry["sha256"]
                if not isinstance(size, int) or not isinstance(sha, str) or len(sha) != 64:
                    raise ValueError("بيانات الحجم أو البصمة غير صالحة.")
            except (ValueError, KeyError) as exc:
                plan.skipped_entries.append({"phone_path": phone_path, "reason": str(exc)})
                continue
            mtime = entry.get("modified_time")
            plan.items.append(
                RestoreItem(
                    original_phone_path=original,
                    target_phone_path=target,
                    local_path=local,
                    relative_path=str(entry.get("relative_path")),
                    size=size,
                    sha256=sha.lower(),
                    modified_time=mtime if isinstance(mtime, int) else 0,
                )
            )
        plan.items.sort(key=lambda item: item.target_phone_path)
        return plan

    # --------------------------------------------------------------- execute
    def restore(
        self,
        serial: str,
        plan: RestorePlan,
        *,
        conflict_policy: str = "skip",
        cancel_event: threading.Event | None = None,
        progress_callback: Callable[[RestoreProgress], None] | None = None,
        media_scan: bool = True,
    ) -> RestoreResult:
        if conflict_policy not in {"skip", "rename"}:
            raise ValueError("سياسة التعارض غير معروفة.")
        result = RestoreResult()
        total_bytes = plan.total_bytes
        done_bytes = 0
        started = time.monotonic()
        self._log(plan.backup_directory, {"event": "restore_started", "files": len(plan.items), "mode": plan.mode})

        for index, item in enumerate(plan.items):
            if cancel_event is not None and cancel_event.is_set():
                result.cancelled = True
                break
            self._progress(progress_callback, plan, index, total_bytes, done_bytes, item.target_phone_path, started)
            try:
                outcome = self._restore_one(serial, item, conflict_policy, media_scan)
            except (AdbCommandError, PhoneWriteRefused, RestoreError, OSError) as exc:
                outcome = RestoreOutcome(item.original_phone_path, item.target_phone_path, "failed", str(exc))
            except AdbError as exc:
                result.outcomes.append(
                    RestoreOutcome(item.original_phone_path, item.target_phone_path, "failed", exc.message_ar)
                )
                result.interrupted = True
                self._log(plan.backup_directory, {"event": "restore_interrupted", "error": exc.message_ar})
                break
            result.outcomes.append(outcome)
            done_bytes += item.size
            self._log(
                plan.backup_directory,
                {
                    "event": "file_restore",
                    "phone_path": outcome.target_phone_path,
                    "status": outcome.status,
                    "detail": outcome.detail,
                },
            )
        self._progress(progress_callback, plan, len(result.outcomes), total_bytes, done_bytes, None, started)
        self._log(plan.backup_directory, {"event": "restore_finished", **{k: v for k, v in result.to_dict().items() if k != "outcomes"}})
        return result

    def _restore_one(self, serial: str, item: RestoreItem, conflict_policy: str, media_scan: bool) -> RestoreOutcome:
        # 1) The local backup copy must still match the signed manifest.
        if item.local_path.is_symlink() or not item.local_path.is_file():
            return RestoreOutcome(item.original_phone_path, item.target_phone_path, "local_damaged", "الملف مفقود من النسخة.")
        if item.local_path.stat().st_size != item.size or not hmac.compare_digest(
            sha256_file(item.local_path), item.sha256
        ):
            return RestoreOutcome(
                item.original_phone_path, item.target_phone_path, "local_damaged",
                "ملف النسخة لا يطابق بصمة manifest؛ لم تتم استعادته.",
            )

        # 2) Never overwrite phone files.
        target = item.target_phone_path
        status = "restored"
        if self.writer.path_exists(serial, target):
            remote_hash = self.writer.remote_sha256(serial, target)
            remote_stat = self.writer.remote_stat(serial, target)
            if remote_hash is not None and hmac.compare_digest(remote_hash, item.sha256):
                return RestoreOutcome(item.original_phone_path, target, "already_present", "الملف موجود ومطابق على الهاتف.")
            if remote_hash is None and remote_stat is not None and remote_stat[0] == item.size:
                return RestoreOutcome(
                    item.original_phone_path, target, "conflict_skipped",
                    "يوجد ملف بنفس الاسم والحجم ولا يمكن مقارنة بصمته؛ لم يُستبدل.",
                ) if conflict_policy == "skip" else self._rename_target(serial, item, target)
            if conflict_policy == "skip":
                return RestoreOutcome(item.original_phone_path, target, "conflict_skipped", "يوجد ملف مختلف بنفس الاسم؛ لم يُستبدل.")
            return self._rename_target(serial, item, target)
        return self._push_verified(serial, item, target, status, media_scan)

    def _rename_target(self, serial: str, item: RestoreItem, target: str) -> RestoreOutcome:
        for attempt in range(1, 1000):
            candidate = _renamed_candidate(target, attempt)
            if not self.writer.path_exists(serial, candidate):
                return self._push_verified(serial, item, candidate, "renamed", True)
        return RestoreOutcome(item.original_phone_path, target, "failed", "تعذّر إيجاد اسم بديل متاح.")

    def _push_verified(self, serial: str, item: RestoreItem, target: str, status: str, media_scan: bool) -> RestoreOutcome:
        directory, name = posixpath.split(target)
        self.writer.make_directories(serial, directory)
        temporary = posixpath.join(directory, f".{name}.pmv-restore-{uuid.uuid4().hex}.part")
        try:
            self.writer.push_file(serial, item.local_path, temporary, timeout=self.push_timeout)
            remote_hash = self.writer.remote_sha256(serial, temporary)
            if remote_hash is not None:
                if not hmac.compare_digest(remote_hash, item.sha256):
                    raise RestoreError("بصمة الملف على الهاتف لا تطابق النسخة بعد النقل.")
            else:
                remote_stat = self.writer.remote_stat(serial, temporary)
                if remote_stat is None or remote_stat[0] != item.size:
                    raise RestoreError("حجم الملف على الهاتف لا يطابق النسخة بعد النقل.")
            self.writer.rename(serial, temporary, target)
            if self.writer.path_exists(serial, temporary):
                # mv -n refused because the target appeared during the push.
                raise RestoreError("ظهر ملف آخر في المسار الهدف أثناء الاستعادة؛ لم يُستبدل.")
        except Exception:
            try:
                if self.writer.path_exists(serial, temporary):
                    self.writer.delete_file(serial, temporary)
            except Exception:  # pragma: no cover - best-effort cleanup
                pass
            raise
        if item.modified_time > 0:
            self.writer.set_modified_time(serial, target, item.modified_time)
        if media_scan:
            try:
                self.writer.media_scan(serial, target)
            except Exception:  # pragma: no cover - best effort
                pass
        detail = None if status == "restored" else f"استُعيد باسم جديد: {target}"
        return RestoreOutcome(item.original_phone_path, target, status, detail)

    @staticmethod
    def _progress(callback, plan: RestorePlan, done: int, total_bytes: int, done_bytes: int, current: str | None, started: float) -> None:
        if callback is None:
            return
        elapsed = max(time.monotonic() - started, 0.001)
        speed = done_bytes / elapsed
        eta = (total_bytes - done_bytes) / speed if speed > 0 else None
        callback(RestoreProgress(len(plan.items), done, total_bytes, done_bytes, current, speed, eta))

    @staticmethod
    def _log(backup_directory: Path, event: dict[str, object]) -> None:
        line = json.dumps(
            {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), **event},
            ensure_ascii=True,
            sort_keys=True,
        )
        try:
            with open(backup_directory / RESTORE_LOG_FILE, "a", encoding="utf-8", newline="\n") as stream:
                stream.write(line + "\n")
        except OSError:
            pass  # read-only backup media must not block a restore
