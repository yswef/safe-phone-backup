"""Safe wipe: free phone space by deleting ONLY files proven to be backed up.

A phone file is eligible for deletion only when **all** of these hold:

1. the backup manifest signature is valid and (if supplied) trusted locally;
2. the backup belongs to the connected phone (serial or hashed serial);
3. the manifest entry is ``verified`` and its local copy exists and matches the
   signed size and SHA-256 right now;
4. the live phone file still has the recorded size and modification time, and
   the phone's own ``sha256sum`` equals the signed hash. Phones without
   ``sha256sum`` are never wiped (fail closed);
5. the user typed the explicit confirmation phrase.

Immediately before each deletion, the phone stat + hash is re-checked, and
only one regular file is removed (no recursion, no directories). Every action
is appended to ``wipe_log.txt`` inside the backup folder.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Protocol

from .adb_manager import AdbCommandError, AdbError, AdbManager
from .adb_writer import PhoneWriteRefused, validate_writable_phone_path
from .backup_engine import sha256_file
from .verifier import load_signed_manifest, safe_manifest_path

WIPE_LOG_FILE = "wipe_log.txt"
WIPE_CONFIRMATION_PHRASES = ("احذف الملفات المنسوخة", "DELETE BACKED UP FILES")
PLAN_MAX_AGE_SECONDS = 30 * 60


class WipeError(RuntimeError):
    def __init__(self, message_ar: str, details: str | None = None) -> None:
        super().__init__(message_ar)
        self.message_ar = message_ar
        self.details = details

    def __str__(self) -> str:
        return f"{self.message_ar}\n{self.details}" if self.details else self.message_ar


class WipeWriter(Protocol):
    def remote_stat(self, serial: str, phone_path: str) -> tuple[int, int] | None: ...
    def remote_sha256(self, serial: str, phone_path: str) -> str | None: ...
    def delete_file(self, serial: str, phone_path: str) -> None: ...
    def media_scan(self, serial: str, phone_path: str) -> None: ...


@dataclass(frozen=True)
class WipeCandidate:
    phone_path: str
    size: int
    modified_time: int
    sha256: str
    local_path: Path


@dataclass(frozen=True)
class WipeRejection:
    phone_path: str
    reason_ar: str


@dataclass
class WipePlan:
    backup_directory: Path
    serial: str
    created_monotonic: float
    eligible: list[WipeCandidate] = field(default_factory=list)
    rejected: list[WipeRejection] = field(default_factory=list)

    @property
    def eligible_bytes(self) -> int:
        return sum(item.size for item in self.eligible)

    def to_dict(self) -> dict[str, object]:
        return {
            "backup_directory": str(self.backup_directory),
            "eligible_count": len(self.eligible),
            "eligible_bytes": self.eligible_bytes,
            "rejected_count": len(self.rejected),
            "eligible": [item.phone_path for item in self.eligible],
            "rejected": [{"phone_path": r.phone_path, "reason_ar": r.reason_ar} for r in self.rejected],
        }


@dataclass(frozen=True)
class WipeProgress:
    files_total: int
    files_done: int
    current_phone_path: str | None


@dataclass
class WipeResult:
    deleted: list[str] = field(default_factory=list)
    skipped: list[WipeRejection] = field(default_factory=list)
    failed: list[WipeRejection] = field(default_factory=list)
    freed_bytes: int = 0
    cancelled: bool = False
    interrupted: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "deleted_count": len(self.deleted),
            "freed_bytes": self.freed_bytes,
            "skipped": [{"phone_path": r.phone_path, "reason_ar": r.reason_ar} for r in self.skipped],
            "failed": [{"phone_path": r.phone_path, "reason_ar": r.reason_ar} for r in self.failed],
            "cancelled": self.cancelled,
            "interrupted": self.interrupted,
        }


def _device_matches(manifest: dict[str, object], serial: str) -> bool:
    device = manifest.get("device")
    if not isinstance(device, dict):
        return False
    stored = device.get("serial")
    if not isinstance(stored, str):
        return False
    if device.get("serial_hashed"):
        return hmac.compare_digest(stored, hashlib.sha256(serial.encode("utf-8")).hexdigest())
    return hmac.compare_digest(stored, serial)


class SafeWipe:
    def __init__(self, writer: WipeWriter, *, trusted_public_key_bytes: bytes | None = None) -> None:
        self.writer = writer
        self.trusted_public_key_bytes = trusted_public_key_bytes

    def plan(
        self,
        serial: str,
        backup_directory: str | os.PathLike[str],
        *,
        selected_phone_paths: Iterable[str] | None = None,
        cancel_event: threading.Event | None = None,
        progress_callback: Callable[[WipeProgress], None] | None = None,
    ) -> WipePlan:
        backup_dir = Path(backup_directory).resolve()
        try:
            manifest, valid, trusted = load_signed_manifest(
                backup_dir, trusted_public_key_bytes=self.trusted_public_key_bytes
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise WipeError("تعذّر قراءة manifest النسخة الاحتياطية.", str(exc)) from exc
        if not valid:
            raise WipeError("توقيع النسخة غير صالح؛ الحذف الآمن غير مسموح.")
        if trusted is False:
            raise WipeError("النسخة موقعة بمفتاح غير موثوق على هذا الكمبيوتر؛ الحذف غير مسموح.")
        if not _device_matches(manifest, serial):
            raise WipeError("هذه النسخة تخص هاتفاً آخر؛ لا يمكن استخدامها لحذف ملفات هذا الهاتف.")

        selection = (
            {AdbManager.validate_phone_path(p) for p in selected_phone_paths}
            if selected_phone_paths is not None
            else None
        )
        entries = [e for e in manifest.get("files", []) if isinstance(e, dict)]
        if selection is not None:
            entries = [e for e in entries if e.get("original_phone_path") in selection]
        plan = WipePlan(backup_directory=backup_dir, serial=serial, created_monotonic=time.monotonic())

        for index, entry in enumerate(entries):
            if cancel_event is not None and cancel_event.is_set():
                raise WipeError("أُلغي فحص الحذف الآمن.")
            phone_path = str(entry.get("original_phone_path", ""))
            if progress_callback is not None:
                progress_callback(WipeProgress(len(entries), index, phone_path))
            reason = self._check_entry(serial, backup_dir, entry)
            if isinstance(reason, WipeCandidate):
                plan.eligible.append(reason)
            else:
                plan.rejected.append(WipeRejection(phone_path, reason))
        if progress_callback is not None:
            progress_callback(WipeProgress(len(entries), len(entries), None))
        return plan

    def _check_entry(self, serial: str, backup_dir: Path, entry: dict[str, object]) -> WipeCandidate | str:
        phone_path = entry.get("original_phone_path")
        if not isinstance(phone_path, str):
            return "مسار الهاتف مفقود في manifest."
        if entry.get("status") != "verified":
            return "الملف لم يُنسخ بنجاح في هذه النسخة."
        size, mtime, sha = entry.get("size"), entry.get("modified_time"), entry.get("sha256")
        if not isinstance(size, int) or not isinstance(mtime, int) or not isinstance(sha, str) or len(sha) != 64:
            return "بيانات الملف في manifest غير مكتملة."
        try:
            path = validate_writable_phone_path(phone_path)
            local = safe_manifest_path(backup_dir, entry.get("relative_path"))
        except (ValueError, PhoneWriteRefused) as exc:
            return str(exc)
        try:
            if local.is_symlink() or not local.is_file() or local.stat().st_size != size:
                return "النسخة المحلية مفقودة أو حجمها لا يطابق."
            if not hmac.compare_digest(sha256_file(local), sha.lower()):
                return "النسخة المحلية تالفة (البصمة لا تطابق)."
        except OSError as exc:
            return f"تعذّرت قراءة النسخة المحلية: {exc}"
        live = self._live_check(serial, path, size, mtime, sha.lower())
        if live is not None:
            return live
        return WipeCandidate(path, size, mtime, sha.lower(), local)

    def _live_check(self, serial: str, path: str, size: int, mtime: int, sha: str) -> str | None:
        try:
            stat = self.writer.remote_stat(serial, path)
        except AdbCommandError:
            return "الملف غير موجود على الهاتف أو تعذّرت قراءته."
        if stat is None:
            return "تعذّر قراءة بيانات الملف على الهاتف."
        if stat != (size, mtime):
            return "تغيّر الملف على الهاتف منذ النسخ (الحجم أو وقت التعديل)."
        remote_hash = self.writer.remote_sha256(serial, path)
        if remote_hash is None:
            return "الهاتف لا يدعم sha256sum؛ لا يمكن تأكيد التطابق فلن يُحذف."
        if not hmac.compare_digest(remote_hash.lower(), sha):
            return "بصمة الملف على الهاتف تختلف عن النسخة."
        return None

    def execute(
        self,
        plan: WipePlan,
        confirmation: str,
        *,
        cancel_event: threading.Event | None = None,
        progress_callback: Callable[[WipeProgress], None] | None = None,
        media_scan: bool = True,
    ) -> WipeResult:
        if confirmation.strip() not in WIPE_CONFIRMATION_PHRASES:
            raise WipeError("عبارة التأكيد غير صحيحة؛ لم يُحذف أي ملف.")
        if time.monotonic() - plan.created_monotonic > PLAN_MAX_AGE_SECONDS:
            raise WipeError("خطة الحذف قديمة؛ أعد الفحص قبل الحذف.")
        result = WipeResult()
        self._log(plan.backup_directory, {"event": "wipe_started", "files": len(plan.eligible)})
        for index, candidate in enumerate(plan.eligible):
            if cancel_event is not None and cancel_event.is_set():
                result.cancelled = True
                break
            if progress_callback is not None:
                progress_callback(WipeProgress(len(plan.eligible), index, candidate.phone_path))
            try:
                # Re-check the local copy and the live phone file right before delete.
                if not candidate.local_path.is_file() or not hmac.compare_digest(
                    sha256_file(candidate.local_path), candidate.sha256
                ):
                    reason = "النسخة المحلية تغيّرت منذ الفحص."
                else:
                    reason = self._live_check(
                        plan.serial, candidate.phone_path, candidate.size, candidate.modified_time, candidate.sha256
                    )
                if reason is not None:
                    result.skipped.append(WipeRejection(candidate.phone_path, reason))
                    self._log(plan.backup_directory, {"event": "wipe_skipped", "phone_path": candidate.phone_path, "reason": reason})
                    continue
                self.writer.delete_file(plan.serial, candidate.phone_path)
            except (AdbCommandError, OSError, PhoneWriteRefused) as exc:
                result.failed.append(WipeRejection(candidate.phone_path, str(exc)))
                self._log(plan.backup_directory, {"event": "wipe_failed", "phone_path": candidate.phone_path, "error": str(exc)})
                continue
            except AdbError as exc:
                result.interrupted = True
                result.failed.append(WipeRejection(candidate.phone_path, exc.message_ar))
                self._log(plan.backup_directory, {"event": "wipe_interrupted", "error": exc.message_ar})
                break
            result.deleted.append(candidate.phone_path)
            result.freed_bytes += candidate.size
            self._log(
                plan.backup_directory,
                {"event": "file_deleted", "phone_path": candidate.phone_path, "sha256": candidate.sha256, "size": candidate.size},
            )
            if media_scan:
                try:
                    self.writer.media_scan(plan.serial, candidate.phone_path)
                except Exception:  # pragma: no cover - best effort
                    pass
        if progress_callback is not None:
            progress_callback(WipeProgress(len(plan.eligible), len(plan.eligible), None))
        self._log(
            plan.backup_directory,
            {"event": "wipe_finished", "deleted": len(result.deleted), "freed_bytes": result.freed_bytes,
             "skipped": len(result.skipped), "failed": len(result.failed)},
        )
        return result

    @staticmethod
    def _log(backup_directory: Path, event: dict[str, object]) -> None:
        line = json.dumps(
            {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), **event},
            ensure_ascii=True,
            sort_keys=True,
        )
        with open(backup_directory / WIPE_LOG_FILE, "a", encoding="utf-8", newline="\n") as stream:
            stream.write(line + "\n")
