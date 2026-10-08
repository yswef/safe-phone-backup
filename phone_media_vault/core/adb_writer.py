"""Explicit phone-write operations used only by restore and safe wipe.

:class:`~phone_media_vault.core.adb_manager.AdbManager` is intentionally
read-only. Everything that can change the phone lives here so that callers have
to opt in deliberately. Every path is validated, limited to shared storage, and
quoted with :func:`shlex.quote`; Android/data, Android/obb, and WhatsApp
Databases/Backups are refused for writes and deletes.
"""

from __future__ import annotations

import os
import posixpath
import re
import shlex

from .adb_manager import AdbCommandError, AdbManager, _PROTECTED_STORAGE_RELATIVE_PATHS

_EMULATED_VOLUME_RE = re.compile(r"^(/storage/emulated/[0-9]+)(?:/.*)?$", re.DOTALL)
_SD_VOLUME_RE = re.compile(r"^(/storage/[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})(?:/.*)?$", re.DOTALL)


class PhoneWriteRefused(ValueError):
    """A write/delete target outside the allowed shared-storage area."""


def shared_volume_root(path: str) -> str | None:
    if path == "/sdcard" or path.startswith("/sdcard/"):
        return "/sdcard"
    for pattern in (_EMULATED_VOLUME_RE, _SD_VOLUME_RE):
        match = pattern.fullmatch(path)
        if match:
            return match.group(1)
    return None


def validate_writable_phone_path(path: str) -> str:
    """Return a normalized shared-storage file path that may be written/deleted."""

    normalized = AdbManager.validate_phone_path(path)
    volume = shared_volume_root(normalized)
    if volume is None:
        raise PhoneWriteRefused("يُسمح بالكتابة/الحذف داخل التخزين المشترك فقط (/sdcard أو بطاقة SD).")
    if normalized == volume:
        raise PhoneWriteRefused("لا يمكن الكتابة أو الحذف على جذر وحدة التخزين.")
    relative = posixpath.relpath(normalized, volume)
    parts = tuple(part.casefold() for part in relative.split("/"))
    for protected in _PROTECTED_STORAGE_RELATIVE_PATHS:
        lowered = tuple(component.casefold() for component in protected)
        if parts[: len(lowered)] == lowered:
            raise PhoneWriteRefused("هذا المسار محمي (Android/data أو obb أو قاعدة بيانات واتساب).")
    return normalized


class AdbWriter:
    """Phone write/delete operations; wraps an :class:`AdbManager`."""

    def __init__(self, adb: AdbManager) -> None:
        self.adb = adb

    # Read helpers re-exported for restore/wipe convenience.
    def remote_stat(self, serial: str, phone_path: str):
        return self.adb.remote_stat(serial, phone_path)

    def remote_sha256(self, serial: str, phone_path: str):
        return self.adb.remote_sha256(serial, phone_path)

    def path_exists(self, serial: str, phone_path: str) -> bool:
        path = AdbManager.validate_phone_path(phone_path)
        command = f"if [ -e {shlex.quote(path)} ] || [ -L {shlex.quote(path)} ]; then printf '1'; else printf '0'; fi"
        result = self.adb.run_shell(serial, command, check=False)
        if result.returncode != 0:
            self.adb._raise_on_failure(result, "تعذّر التحقق من وجود الملف على الهاتف.")
        return result.stdout_text == "1"

    def make_directories(self, serial: str, phone_dir: str) -> None:
        path = validate_writable_phone_path(phone_dir)
        result = self.adb.run_shell(serial, f"mkdir -p {shlex.quote(path)}", check=False)
        self.adb._raise_on_failure(result, "تعذّر إنشاء المجلد على الهاتف.")

    def push_file(
        self,
        serial: str,
        local_path: str | os.PathLike[str],
        phone_path: str,
        *,
        timeout: float | None = None,
    ) -> None:
        remote = validate_writable_phone_path(phone_path)
        local = os.fspath(local_path)
        if not os.path.isfile(local):
            raise ValueError("الملف المحلي غير موجود.")
        result = self.adb._run_raw(("push", local, remote), serial=serial, timeout=timeout)
        self.adb._raise_on_failure(result, "تعذّر نقل الملف إلى الهاتف.")

    def rename(self, serial: str, source: str, destination: str) -> None:
        src = validate_writable_phone_path(source)
        dst = validate_writable_phone_path(destination)
        # mv -n never replaces an existing destination.
        result = self.adb.run_shell(
            serial, f"mv -n {shlex.quote(src)} {shlex.quote(dst)}", check=False
        )
        self.adb._raise_on_failure(result, "تعذّر إعادة تسمية الملف على الهاتف.")

    def set_modified_time(self, serial: str, phone_path: str, epoch_seconds: int) -> bool:
        path = validate_writable_phone_path(phone_path)
        result = self.adb.run_shell(
            serial, f"touch -m -d @{int(epoch_seconds)} {shlex.quote(path)}", check=False
        )
        return result.returncode == 0

    def delete_file(self, serial: str, phone_path: str) -> None:
        """Delete exactly one regular file (never directories, never recursive)."""

        path = validate_writable_phone_path(phone_path)
        quoted = shlex.quote(path)
        command = (
            f"if [ -f {quoted} ] && [ ! -L {quoted} ]; then rm -f -- {quoted} && printf 'DELETED'; "
            "else printf 'NOTFILE'; fi"
        )
        result = self.adb.run_shell(serial, command, check=False)
        self.adb._raise_on_failure(result, "تعذّر حذف الملف من الهاتف.")
        if result.stdout_text != "DELETED":
            raise AdbCommandError("لم يُحذف الملف لأنه ليس ملفاً عادياً على الهاتف.", path)

    def media_scan(self, serial: str, phone_path: str) -> None:
        """Best-effort request for Android to refresh its media index."""

        path = AdbManager.validate_phone_path(phone_path)
        uri = "file://" + path
        self.adb.run_shell(
            serial,
            "am broadcast -a android.intent.action.MEDIA_SCANNER_SCAN_FILE -d "
            + shlex.quote(uri),
            check=False,
            timeout=20.0,
        )
