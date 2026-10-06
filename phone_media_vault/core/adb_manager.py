"""Safe, shell-injection-resistant ADB access for Android storage scans.

This module only reads device state and file metadata. It contains no phone
write/delete operations; restore and wipe support will live in separate modules
and will require explicit confirmation in the UI.
"""

from __future__ import annotations

import os
import posixpath
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Sequence

from .models import DeviceInfo, RemoteFileIssue, RemoteFileStat, RemoteListing


_EMULATED_VOLUME_RE = re.compile(r"^(/storage/emulated/[0-9]+)(?:/.*)?$", re.DOTALL)
_SD_VOLUME_RE = re.compile(
    r"^(/storage/[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})(?:/.*)?$",
    re.DOTALL,
)
_PROTECTED_STORAGE_RELATIVE_PATHS = (
    ("Android", "data"),
    ("Android", "obb"),
    ("WhatsApp", "Databases"),
    ("WhatsApp", "Backups"),
    ("Android", "media", "com.whatsapp", "WhatsApp", "Databases"),
    ("Android", "media", "com.whatsapp", "WhatsApp", "Backups"),
)


class AdbError(RuntimeError):
    """Base exception whose primary message is suitable for an Arabic UI."""

    def __init__(self, message_ar: str, details: str | None = None) -> None:
        super().__init__(message_ar)
        self.message_ar = message_ar
        self.details = details

    def __str__(self) -> str:
        if self.details:
            return f"{self.message_ar}\n{self.details}"
        return self.message_ar


class AdbNotFoundError(AdbError):
    def __init__(self) -> None:
        super().__init__(
            "تعذّر العثور على Android Platform-Tools (ADB). "
            "ضع ملفات platform-tools داخل مجلد التطبيق أو ثبّت ADB وأضفه إلى PATH."
        )


class AdbTimeoutError(AdbError):
    def __init__(self, timeout: float) -> None:
        super().__init__(f"انتهت مهلة الاتصال بـ ADB بعد {timeout:g} ثانية.")


class AdbCommandError(AdbError):
    pass


class AdbTransportError(AdbError):
    """ADB transport/device loss (distinct from a per-file permission error)."""


class NoDeviceConnectedError(AdbError):
    def __init__(self) -> None:
        super().__init__(
            "لم يتم العثور على هاتف Android عبر USB. تحقّق من الكابل، "
            "وفعّل تصحيح USB، ثم أعد توصيل الهاتف."
        )


class DeviceNotFoundError(AdbError):
    def __init__(self, serial: str) -> None:
        super().__init__(f"الهاتف المحدد غير ظاهر في قائمة ADB: {serial}")


class DeviceUnauthorizedError(AdbError):
    def __init__(self, serial: str) -> None:
        super().__init__(
            "الهاتف متصل، لكن لم تتم الموافقة على تصحيح USB. افتح شاشة الهاتف، "
            "وافق على نافذة بصمة RSA، ثم أعد المحاولة.",
            f"Serial: {serial}",
        )


class DeviceOfflineError(AdbError):
    def __init__(self, serial: str) -> None:
        super().__init__(
            "الهاتف ظاهر لدى ADB لكنه غير متصل حالياً. أعد توصيل كابل USB "
            "وتأكد من اختيار وضع نقل الملفات.",
            f"Serial: {serial}",
        )


class MultipleDevicesError(AdbError):
    def __init__(self, devices: Sequence[DeviceInfo]) -> None:
        listing = "، ".join(f"{item.serial} ({item.state})" for item in devices)
        super().__init__(
            "تم العثور على أكثر من جهاز Android. اختر الهاتف المطلوب صراحةً قبل المتابعة.",
            listing,
        )
        self.devices = tuple(devices)


@dataclass(frozen=True)
class AdbCommandResult:
    """Raw result for an ADB invocation (bytes are preserved for NUL records)."""

    returncode: int
    stdout: bytes
    stderr: bytes

    @property
    def stdout_text(self) -> str:
        return self.stdout.decode("utf-8", errors="replace").strip("\r\n")

    @property
    def stderr_text(self) -> str:
        return self.stderr.decode("utf-8", errors="replace").strip("\r\n")


class AdbManager:
    """Locate ADB and provide explicit-device, read-only Android operations."""

    _SD_CARD_NAME = re.compile(r"^[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}$")

    def __init__(
        self,
        adb_path: str | os.PathLike[str] | None = None,
        *,
        command_timeout: float = 30.0,
    ) -> None:
        if command_timeout <= 0:
            raise ValueError("command_timeout must be greater than zero")
        self.adb_path = self._resolve_adb_path(adb_path)
        self.command_timeout = command_timeout

    @staticmethod
    def _candidate_names() -> tuple[str, ...]:
        if os.name == "nt":
            return ("adb.exe", "adb")
        return ("adb", "adb.exe")

    @classmethod
    def _resolve_adb_path(
        cls, explicit_path: str | os.PathLike[str] | None
    ) -> str:
        names = cls._candidate_names()

        if explicit_path is not None:
            raw = os.fspath(explicit_path)
            candidate = Path(raw).expanduser()
            if candidate.is_dir():
                for name in names:
                    bundled_candidate = candidate / name
                    if bundled_candidate.is_file():
                        return str(bundled_candidate.resolve())
            elif candidate.is_file():
                return str(candidate.resolve())
            else:
                located = shutil.which(raw)
                if located:
                    return located
            raise AdbNotFoundError()

        package_root = Path(__file__).resolve().parents[1]
        executable_root = Path(sys.executable).resolve().parent
        bundled_directories = (
            package_root / "platform-tools",
            executable_root / "platform-tools",
            executable_root / "_internal" / "platform-tools",
        )
        for directory in bundled_directories:
            for name in names:
                candidate = directory / name
                if candidate.is_file():
                    return str(candidate.resolve())

        located = shutil.which("adb") or shutil.which("adb.exe")
        if located:
            return located
        raise AdbNotFoundError()

    @staticmethod
    def validate_phone_path(path: str) -> str:
        """Return a normalized absolute POSIX path, rejecting traversal paths.

        Newlines and spaces are permitted because Android filenames may contain
        them; every use in a shell command is quoted with :func:`shlex.quote`.
        """

        if not isinstance(path, str) or not path:
            raise ValueError("مسار الهاتف فارغ.")
        if "\x00" in path:
            raise ValueError("مسار الهاتف يحتوي على محرف غير صالح.")
        if not path.startswith("/"):
            raise ValueError("يجب أن يكون مسار الهاتف مطلقاً، مثل /sdcard/DCIM.")
        if any(part == ".." for part in path.split("/")):
            raise ValueError("لا يُسمح باستخدام .. في مسار الهاتف.")
        # Android paths are POSIX paths even when the desktop host is Windows.
        normalized = posixpath.normpath(path)
        if not normalized.startswith("/"):
            raise ValueError("مسار الهاتف غير صالح.")
        return normalized

    @staticmethod
    def _decode_phone_text(value: bytes) -> str:
        # surrogateescape preserves unusual non-UTF-8 Android filename bytes on
        # POSIX hosts instead of silently changing the path.
        return value.decode("utf-8", errors="surrogateescape")

    @staticmethod
    def _check_serial(serial: str) -> str:
        if not isinstance(serial, str) or not serial or "\x00" in serial:
            raise ValueError("يجب تحديد رقم الهاتف التسلسلي من قائمة ADB.")
        return serial

    def _run_raw(
        self,
        arguments: Sequence[str],
        *,
        serial: str | None = None,
        timeout: float | None = None,
    ) -> AdbCommandResult:
        command = [self.adb_path]
        if serial is not None:
            command.extend(("-s", self._check_serial(serial)))
        command.extend(str(argument) for argument in arguments)

        run_options: dict[str, object] = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "timeout": self.command_timeout if timeout is None else timeout,
            "check": False,
            "shell": False,
        }
        if os.name == "nt":
            run_options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        effective_timeout = self.command_timeout if timeout is None else timeout
        try:
            completed = subprocess.run(command, **run_options)
        except FileNotFoundError as exc:
            raise AdbNotFoundError() from exc
        except subprocess.TimeoutExpired as exc:
            raise AdbTimeoutError(effective_timeout) from exc
        except OSError as exc:
            raise AdbCommandError(
                "تعذّر تشغيل ADB على هذا الكمبيوتر.", str(exc)
            ) from exc

        return AdbCommandResult(
            returncode=int(completed.returncode),
            stdout=completed.stdout or b"",
            stderr=completed.stderr or b"",
        )

    @staticmethod
    def _failure_detail(result: AdbCommandResult) -> str | None:
        detail = result.stderr_text or result.stdout_text
        if not detail:
            return None
        return detail[:3000]

    @staticmethod
    def _is_transport_failure(result: AdbCommandResult) -> bool:
        text = "\n".join((result.stderr_text, result.stdout_text)).casefold()
        return any(
            marker in text
            for marker in (
                "device offline",
                "device unauthorized",
                "device disconnected",
                "device not found",
                "no devices/emulators found",
                "more than one device/emulator",
                "transport error",
                "transport is closing",
                "connection reset",
                "error: closed",
            )
        )

    @classmethod
    def _raise_on_failure(
        cls, result: AdbCommandResult, message_ar: str
    ) -> None:
        if result.returncode != 0:
            details = cls._failure_detail(result)
            if cls._is_transport_failure(result):
                raise AdbTransportError(
                    "انقطع اتصال ADB بالهاتف أو لم يعد الهاتف متاحاً.", details
                )
            raise AdbCommandError(message_ar, details)

    def run_shell(
        self,
        serial: str,
        command: str,
        *,
        check: bool = True,
        timeout: float | None = None,
    ) -> AdbCommandResult:
        """Run one remote shell command for an explicitly selected device.

        ``command`` is interpreted by Android's POSIX shell. Callers must quote
        all data values (paths use :func:`shlex.quote`) and must never pass
        user-provided shell fragments.
        """

        self._check_serial(serial)
        if not isinstance(command, str) or "\x00" in command:
            raise ValueError("أمر ADB غير صالح.")
        result = self._run_raw(("shell", command), serial=serial, timeout=timeout)
        if check:
            self._raise_on_failure(result, "تعذّر تنفيذ أمر القراءة على الهاتف.")
        return result

    def run_exec_out(
        self,
        serial: str,
        command: str,
        *,
        check: bool = True,
        timeout: float | None = None,
    ) -> AdbCommandResult:
        """Run a remote command without a PTY, preserving binary output."""

        self._check_serial(serial)
        if not isinstance(command, str) or "\x00" in command:
            raise ValueError("أمر ADB غير صالح.")
        result = self._run_raw(("exec-out", command), serial=serial, timeout=timeout)
        if check:
            self._raise_on_failure(result, "تعذّر استكشاف ملفات الهاتف عبر ADB.")
        return result

    @staticmethod
    def parse_devices(output: str | bytes) -> list[DeviceInfo]:
        """Parse ``adb devices -l`` output, including unauthorized/offline rows."""

        if isinstance(output, bytes):
            text = output.decode("utf-8", errors="replace")
        else:
            text = output

        devices: list[DeviceInfo] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.lower().startswith("list of devices"):
                continue
            match = re.match(r"^(\S+)\s+(\S+)(?:\s+(.*))?$", line)
            if not match:
                continue
            serial, state, properties_text = match.groups()
            properties: dict[str, str] = {}
            for token in (properties_text or "").split():
                key, separator, value = token.partition(":")
                if separator and key:
                    properties[key] = value

            # Older platform-tools can render this state as two tokens.
            if state == "no" and (properties_text or "").startswith("permissions"):
                state = "no permissions"

            model = properties.get("model", "Unknown").replace("_", " ")
            product = properties.get("product", "Unknown").replace("_", " ")
            device_name = properties.get("device", "Unknown").replace("_", " ")
            devices.append(
                DeviceInfo(
                    serial=serial,
                    state=state,
                    model=model or "Unknown",
                    product=product or "Unknown",
                    device_name=device_name or "Unknown",
                    transport_id=properties.get("transport_id"),
                )
            )
        return devices

    def list_devices(self) -> list[DeviceInfo]:
        result = self._run_raw(("devices", "-l"))
        self._raise_on_failure(result, "تعذّر الحصول على قائمة أجهزة ADB.")
        return self.parse_devices(result.stdout)

    def resolve_device(self, serial: str | None = None) -> DeviceInfo:
        """Require an unambiguous, authorized USB device; never guess between phones."""

        devices = self.list_devices()
        if not devices:
            raise NoDeviceConnectedError()

        if serial is not None:
            selected = next((item for item in devices if item.serial == serial), None)
            if selected is None:
                raise DeviceNotFoundError(serial)
        else:
            if len(devices) > 1:
                raise MultipleDevicesError(devices)
            selected = devices[0]

        if selected.state == "unauthorized":
            raise DeviceUnauthorizedError(selected.serial)
        if selected.state == "offline":
            raise DeviceOfflineError(selected.serial)
        if selected.state != "device":
            raise AdbError(
                "حالة الهاتف لا تسمح بالوصول إليه. افحص اتصال USB ثم أعد المحاولة.",
                f"Serial: {selected.serial}; state: {selected.state}",
            )
        return selected

    def _read_property(self, serial: str, prop: str) -> str:
        result = self.run_shell(serial, f"getprop {shlex.quote(prop)}", check=False)
        if result.returncode != 0:
            self._raise_on_failure(result, "تعذّر قراءة معلومات الهاتف.")
        return result.stdout_text.strip()

    def get_device_info(self, serial: str | None = None) -> DeviceInfo:
        selected = self.resolve_device(serial)
        model = self._read_property(selected.serial, "ro.product.model")
        android_version = self._read_property(selected.serial, "ro.build.version.release")
        return replace(
            selected,
            model=model or selected.model,
            android_version=android_version or "Unknown",
        )

    @staticmethod
    def _sha256_utility_unavailable(text: str) -> bool:
        lowered = text.casefold()
        if "sha256sum" not in lowered:
            return False
        if "no such file or directory" in lowered:
            return False
        return any(
            marker in lowered
            for marker in (
                "not found",
                "inaccessible",
                "unknown command",
                "not recognized",
                "applet not found",
            )
        )

    def remote_stat(self, serial: str, phone_path: str) -> tuple[int, int] | None:
        """Read ``(size, mtime_epoch)`` with toybox stat; None if unavailable."""

        path = self.validate_phone_path(phone_path)
        result = self.run_shell(
            serial,
            f"stat -c '%s %Y' {shlex.quote(path)}",
            check=False,
            timeout=60.0,
        )
        output = result.stdout_text
        error_text = "\n".join(part for part in (output, result.stderr_text) if part)
        if result.returncode != 0:
            lowered = error_text.casefold()
            if "stat" in lowered and any(
                marker in lowered
                for marker in ("not found", "inaccessible", "unknown command", "applet not found")
            ):
                return None
            self._raise_on_failure(result, "تعذّر قراءة بيانات الملف على الهاتف.")
        match = re.fullmatch(r"\s*(\d+)\s+(-?\d+)\s*", output)
        if not match:
            return None
        return int(match.group(1)), int(match.group(2))

    def remote_sha256(self, serial: str, phone_path: str) -> str | None:
        """Hash one device file with toybox sha256sum; return None if unavailable."""

        path = self.validate_phone_path(phone_path)
        result = self.run_shell(
            serial, f"sha256sum {shlex.quote(path)}", check=False, timeout=60.0
        )
        output = result.stdout_text
        error_text = "\n".join(part for part in (output, result.stderr_text) if part)
        if result.returncode != 0:
            if self._sha256_utility_unavailable(error_text):
                return None
            self._raise_on_failure(result, "تعذّر حساب بصمة الملف على الهاتف.")

        match = re.match(r"^\s*([0-9a-fA-F]{64})(?:\s|$)", output)
        if match:
            return match.group(1).lower()
        if self._sha256_utility_unavailable(error_text):
            return None
        raise AdbCommandError(
            "لم يُرجع الهاتف بصمة SHA-256 صالحة.",
            error_text[:3000] if error_text else None,
        )

    def pull_file(
        self,
        serial: str,
        phone_path: str,
        local_path: str | os.PathLike[str],
        *,
        preserve_timestamps: bool = True,
        timeout: float | None = None,
    ) -> AdbCommandResult:
        """Pull one regular file with argv-based ADB invocation (no local shell)."""

        remote = self.validate_phone_path(phone_path)
        local = os.fspath(local_path)
        if not local or "\x00" in local:
            raise ValueError("مسار الوجهة على الكمبيوتر غير صالح.")
        arguments = ["pull"]
        if preserve_timestamps:
            arguments.append("-a")
        arguments.extend((remote, local))
        result = self._run_raw(arguments, serial=serial, timeout=timeout)
        self._raise_on_failure(result, "تعذّر نسخ الملف من الهاتف.")
        return result

    def is_directory(self, serial: str, phone_path: str) -> bool:
        path = self.validate_phone_path(phone_path)
        command = (
            f"if [ -d {shlex.quote(path)} ]; then printf '1'; "
            "else printf '0'; fi"
        )
        result = self.run_shell(serial, command, check=False)
        if result.returncode != 0:
            self._raise_on_failure(result, "تعذّر التحقق من مجلد الهاتف.")
        return result.stdout_text == "1"

    @staticmethod
    def _parse_nul_paths(output: bytes) -> list[str]:
        paths: list[str] = []
        for raw_path in output.split(b"\x00"):
            if raw_path:
                paths.append(AdbManager._decode_phone_text(raw_path))
        return paths

    def list_directories(self, serial: str, phone_path: str) -> list[str]:
        """List immediate subdirectories using NUL delimiters."""

        path = self.validate_phone_path(phone_path)
        command = (
            f"find {shlex.quote(path)} -mindepth 1 -maxdepth 1 "
            "-type d -print0"
        )
        result = self.run_exec_out(serial, command, check=False)
        if result.returncode != 0 and not result.stdout:
            self._raise_on_failure(result, "تعذّر فحص وحدات التخزين في الهاتف.")
        return self._parse_nul_paths(result.stdout)

    @staticmethod
    def parse_remote_file_listing(output: bytes) -> RemoteListing:
        """Decode the scanner's NUL-delimited F/E records.

        Success record: ``F NUL size NUL mtime NUL absolute-path NUL``.
        Per-file metadata error: ``E NUL absolute-path NUL``.
        Skipped symbolic link: ``L NUL absolute-path NUL``.
        """

        listing = RemoteListing()
        fields = output.split(b"\x00")
        if fields and fields[-1] == b"":
            fields.pop()

        index = 0
        while index < len(fields):
            record_type = fields[index]
            if record_type == b"F" and index + 3 < len(fields):
                size_raw, mtime_raw, path_raw = fields[index + 1 : index + 4]
                try:
                    size = int(size_raw.decode("ascii"))
                    modified_time = int(mtime_raw.decode("ascii"))
                    if size < 0:
                        raise ValueError("negative size")
                except (UnicodeDecodeError, ValueError):
                    listing.warnings.append(
                        "تجاهل الماسح سجلاً غير صالح لبيانات ملف."
                    )
                    index += 4
                    continue
                listing.files.append(
                    RemoteFileStat(
                        path=AdbManager._decode_phone_text(path_raw),
                        size=size,
                        modified_time=modified_time,
                    )
                )
                index += 4
            elif record_type == b"E" and index + 1 < len(fields):
                path = AdbManager._decode_phone_text(fields[index + 1])
                listing.issues.append(
                    RemoteFileIssue(
                        path=path,
                        message="تعذّر قراءة حجم الملف أو وقت تعديله على الهاتف.",
                    )
                )
                index += 2
            elif record_type == b"L" and index + 1 < len(fields):
                listing.symlinks.append(
                    AdbManager._decode_phone_text(fields[index + 1])
                )
                index += 2
            else:
                listing.warnings.append(
                    "وصلت بيانات مسح غير مكتملة أو غير معروفة من الهاتف."
                )
                break
        return listing

    @staticmethod
    def _shared_storage_root(path: str) -> str | None:
        if path == "/sdcard" or path.startswith("/sdcard/"):
            return "/sdcard"
        match = _EMULATED_VOLUME_RE.fullmatch(path)
        if match:
            return match.group(1)
        match = _SD_VOLUME_RE.fullmatch(path)
        return match.group(1) if match else None

    def list_file_stats(
        self,
        serial: str,
        root_path: str,
        *,
        timeout: float | None = None,
        excluded_paths: Sequence[str] = (),
    ) -> RemoteListing:
        """Recursively list regular files and metadata without following symlinks.

        The remote shell script emits NUL-delimited records, so spaces, Arabic,
        tabs, and newline characters in filenames do not corrupt the listing.
        Permission/stat failures are reported as issues rather than aborting the
        whole folder scan. Android/data, Android/obb, and WhatsApp Databases/
        Backups are always pruned on-device; optional exclusions are pruned too.
        """

        root = self.validate_phone_path(root_path)
        script = r"""
for f do
    meta=$(stat -c '%s %Y' "$f" 2>/dev/null) || {
        printf 'E\000%s\000' "$f"
        continue
    }
    case "$meta" in
        *" "*) size=${meta%% *}; mtime=${meta#* } ;;
        *) printf 'E\000%s\000' "$f"; continue ;;
    esac
    case "$size" in
        ''|*[!0-9]*) printf 'E\000%s\000' "$f"; continue ;;
    esac
    case "$mtime" in
        ''|*[!0-9-]*) printf 'E\000%s\000' "$f"; continue ;;
    esac
    printf 'F\000%s\000%s\000%s\000' "$size" "$mtime" "$f"
done
""".strip()
        auto_exclusions: list[str] = []
        volume_root = self._shared_storage_root(root)
        if volume_root is not None:
            for relative_parts in _PROTECTED_STORAGE_RELATIVE_PATHS:
                excluded_root = posixpath.join(volume_root, *relative_parts)
                if root == excluded_root or root.startswith(excluded_root + "/"):
                    # A caller cannot bypass the privacy exclusions by invoking
                    # the lower-level ADB listing API directly.
                    return RemoteListing()
                try:
                    root_contains_exclusion = (
                        posixpath.commonpath((root, excluded_root)) == root
                    )
                except ValueError:
                    root_contains_exclusion = False
                if root_contains_exclusion:
                    auto_exclusions.append(excluded_root)

        normalized_exclusions: list[str] = []
        for excluded_path in (*excluded_paths, *auto_exclusions):
            excluded = self.validate_phone_path(excluded_path)
            try:
                contained = posixpath.commonpath((root, excluded)) == root
            except ValueError:
                contained = False
            if not contained or excluded == root:
                raise ValueError("مسار الاستثناء يجب أن يكون داخل مجلد المسح.")
            if excluded not in normalized_exclusions:
                normalized_exclusions.append(excluded)

        prune_expression = ""
        if normalized_exclusions:
            predicates = " -o ".join(
                f"-path {shlex.quote(path)}" for path in normalized_exclusions
            )
            prune_expression = f"\\( {predicates} \\) -prune -o "

        symlink_script = r'''for f do printf 'L\000%s\000' "$f"; done'''
        command = (
            f"find {shlex.quote(root)} {prune_expression}"
            f"-type l -exec sh -c {shlex.quote(symlink_script)} sh {{}} + "
            f"-o -type f -exec sh -c {shlex.quote(script)} sh {{}} +"
        )
        result = self.run_exec_out(
            serial, command, check=False, timeout=timeout
        )
        if result.returncode != 0 and self._is_transport_failure(result):
            self._raise_on_failure(result, "انقطع اتصال ADB أثناء استكشاف الملفات.")
        listing = self.parse_remote_file_listing(result.stdout)
        if result.stderr_text:
            listing.warnings.append(result.stderr_text[:3000])
        if result.returncode != 0:
            listing.warnings.append(
                f"اكتمل فحص المجلد برمز ADB غير صفري ({result.returncode})."
            )
        return listing

    def list_sd_card_roots(self, serial: str) -> list[str]:
        """Return mounted removable-storage roots matching XXXX-XXXX."""

        roots: list[str] = []
        for directory in self.list_directories(serial, "/storage"):
            name = directory.rsplit("/", 1)[-1]
            if self._SD_CARD_NAME.fullmatch(name):
                roots.append(directory)
        return sorted(set(roots), key=str.casefold)
