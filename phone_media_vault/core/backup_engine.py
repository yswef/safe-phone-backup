"""Verified Android-to-Windows backup engine.

The phone is read-only here. Every pull lands in a unique ``.part`` file; a
verified file is installed only if its destination is not already occupied.
Android hashes are preferred, with a two-independent-pull fallback when the
phone has no ``sha256sum`` command.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import posixpath
import re
import shutil
import stat
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable, Mapping, Protocol

from .adb_manager import AdbCommandError, AdbError, AdbManager
from .models import DeviceInfo, ScanResult, ScanWarning, ScannedFile
from .signer import (
    ManifestSigner,
    SignatureArtifacts,
    SigningError,
    atomic_write_bytes,
)


_MANIFEST_NAME = "manifest.json"
_BACKUP_LOG_NAME = "backup_log.txt"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SD_VOLUME_RE = re.compile(r"^/storage/([0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})(?:/.*)?$", re.DOTALL)
_EMULATED_VOLUME_RE = re.compile(r"^(/storage/emulated/[0-9]+)(?:/.*)?$", re.DOTALL)
_WINDOWS_RESERVED_NAME_RE = re.compile(
    r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$", re.IGNORECASE
)
_WINDOWS_FORBIDDEN = frozenset('<>:/\\|?*%')


class BackupError(RuntimeError):
    """Base error for backup-stage failures."""

    def __init__(self, message_ar: str, details: str | None = None) -> None:
        super().__init__(message_ar)
        self.message_ar = message_ar
        self.details = details

    def __str__(self) -> str:
        return f"{self.message_ar}\n{self.details}" if self.details else self.message_ar


class BackupDestinationError(BackupError):
    pass


class BackupCancelled(BackupError):
    def __init__(self) -> None:
        super().__init__("أُلغي النسخ الاحتياطي بناءً على طلب المستخدم.")


class FileBackupError(BackupError):
    pass


class BackupAdb(Protocol):
    def remote_stat(self, serial: str, phone_path: str) -> tuple[int, int] | None: ...

    def remote_sha256(self, serial: str, phone_path: str) -> str | None: ...

    def pull_file(
        self,
        serial: str,
        phone_path: str,
        local_path: str | os.PathLike[str],
        *,
        preserve_timestamps: bool = True,
        timeout: float | None = None,
    ): ...


@dataclass(frozen=True)
class BackupProgress:
    files_total: int
    files_done: int
    bytes_total: int
    bytes_processed: int
    bytes_verified: int
    verified_count: int
    skipped_count: int
    failed_count: int
    current_phone_path: str | None
    speed_bytes_per_second: float
    eta_seconds: float | None


@dataclass
class BackupResult:
    backup_directory: Path
    manifest_path: Path
    files_total: int
    verified_count: int
    skipped_count: int
    failed_count: int
    verified_bytes: int
    failed_files: list[dict[str, str]] = field(default_factory=list)
    scan_warnings: list[ScanWarning] = field(default_factory=list)
    cancelled: bool = False
    interrupted: bool = False
    manifest: dict[str, object] = field(default_factory=dict)
    signature: SignatureArtifacts | None = None

    @property
    def fully_verified(self) -> bool:
        return (
            self.files_total > 0
            and not self.cancelled
            and not self.interrupted
            and not self.scan_warnings
            and self.failed_count == 0
            and self.verified_count == self.files_total
        )


@dataclass(frozen=True)
class _BackupTarget:
    scanned_file: ScannedFile
    relative_path: str
    absolute_path: Path


def serialize_manifest(manifest: Mapping[str, object]) -> bytes:
    """Serialize a manifest deterministically; the exact bytes are signed."""

    return (
        json.dumps(
            manifest,
            ensure_ascii=True,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def sha256_file(path: str | os.PathLike[str], chunk_size: int = 1024 * 1024) -> str:
    """Stream a local file's SHA-256 without loading it into memory."""

    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _encode_windows_component(component: str) -> str:
    """Escape Android filename characters forbidden or special on Windows."""

    if component in {"", ".", ".."}:
        raise BackupDestinationError("تحتوي أسماء الملفات على مكوّن مسار غير آمن.")

    output: list[str] = []
    last_index = len(component) - 1
    for index, character in enumerate(component):
        codepoint = ord(character)
        forbidden = (
            character in _WINDOWS_FORBIDDEN
            or codepoint < 32
            or 0xD800 <= codepoint <= 0xDFFF
            or (index == last_index and character in {".", " "})
        )
        if forbidden:
            output.extend(
                f"%{byte:02X}"
                for byte in character.encode("utf-8", errors="surrogateescape")
            )
        else:
            output.append(character)

    encoded = "".join(output)
    if _WINDOWS_RESERVED_NAME_RE.fullmatch(encoded):
        encoded = "_" + encoded
    return encoded


def _phone_volume_and_relative_path(phone_path: str) -> tuple[str, str]:
    """Map shared-storage phone paths to a collision-resistant local namespace."""

    path = AdbManager.validate_phone_path(phone_path)
    if path == "/sdcard" or path.startswith("/sdcard/"):
        volume_root, namespace = "/sdcard", "internal"
    else:
        emulated = _EMULATED_VOLUME_RE.fullmatch(path)
        if emulated:
            volume_root = emulated.group(1)
            user_id = volume_root.rsplit("/", 1)[-1]
            namespace = "internal" if user_id == "0" else f"internal-user-{user_id}"
        else:
            sd_card = _SD_VOLUME_RE.fullmatch(path)
            if not sd_card:
                raise BackupDestinationError(
                    "مسار الملف ليس ضمن وحدة تخزين مشتركة مدعومة.", path
                )
            volume_root = f"/storage/{sd_card.group(1)}"
            namespace = f"sdcard-{sd_card.group(1).casefold()}"

    relative = posixpath.relpath(path, volume_root)
    if relative in {"", ".", ".."} or relative.startswith("../"):
        raise BackupDestinationError("تعذّر تكوين مسار محلي آمن للملف.", path)
    return namespace, relative


def _target_relative_path(phone_path: str) -> str:
    namespace, relative = _phone_volume_and_relative_path(phone_path)
    components = [_encode_windows_component(part) for part in relative.split("/")]
    return PurePosixPath("files", namespace, *components).as_posix()


def _under_directory(path: Path, directory: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(directory.resolve(strict=False))
        return True
    except ValueError:
        return False


def _lexically_under(path: Path, directory: Path) -> bool:
    try:
        path.absolute().relative_to(directory.absolute())
        return True
    except ValueError:
        return False


def _build_targets(
    files: Iterable[ScannedFile], backup_directory: Path
) -> list[_BackupTarget]:
    """Build safe target paths and resolve Windows case-insensitive collisions."""

    indexed: list[tuple[ScannedFile, str]] = []
    seen_phone_paths: set[str] = set()
    for item in files:
        phone_path = AdbManager.validate_phone_path(item.phone_path)
        if phone_path in seen_phone_paths:
            continue
        seen_phone_paths.add(phone_path)
        indexed.append((item, _target_relative_path(phone_path)))

    indexed.sort(key=lambda row: row[0].phone_path)
    used: dict[str, str] = {}
    targets: list[_BackupTarget] = []
    for item, relative in indexed:
        collision_key = relative.casefold()
        existing_phone_path = used.get(collision_key)
        if existing_phone_path is not None and existing_phone_path != item.phone_path:
            path = PurePosixPath(relative)
            suffix = hashlib.sha256(item.phone_path.encode("utf-8", "surrogateescape")).hexdigest()
            candidate = path.with_name(f"{path.name}~{suffix[:12]}").as_posix()
            length = 12
            while candidate.casefold() in used:
                length += 4
                candidate = path.with_name(f"{path.name}~{suffix[:length]}").as_posix()
            relative = candidate
            collision_key = relative.casefold()
        used[collision_key] = item.phone_path

        absolute = backup_directory.joinpath(*PurePosixPath(relative).parts)
        if not _under_directory(absolute, backup_directory):
            raise BackupDestinationError("تعذّر إنشاء مسار آمن داخل مجلد النسخة.")
        targets.append(_BackupTarget(item, relative, absolute))
    return targets


class BackupEngine:
    """Copy, hash, verify, and sign the selected files from one Android device."""

    def __init__(
        self,
        adb: BackupAdb,
        signer: ManifestSigner,
        *,
        app_version: str = "0.1.0-dev",
        max_retries: int = 3,
        pull_timeout: float = 900.0,
    ) -> None:
        if max_retries < 0:
            raise ValueError("max_retries cannot be negative")
        if pull_timeout <= 0:
            raise ValueError("pull_timeout must be greater than zero")
        self.adb = adb
        self.signer = signer
        self.app_version = app_version
        self.max_retries = max_retries
        self.pull_timeout = pull_timeout

    def backup(
        self,
        serial: str,
        device: DeviceInfo,
        files: ScanResult | Iterable[ScannedFile],
        backup_directory: str | os.PathLike[str],
        *,
        hash_serial: bool = False,
        signing_password: str | None = None,
        cancel_event: threading.Event | None = None,
        pause_event: threading.Event | None = None,
        progress_callback: Callable[[BackupProgress], None] | None = None,
        reconnect_callback: Callable[[str, AdbError], bool] | None = None,
    ) -> BackupResult:
        """Back up a scan result; resume only from a valid signed manifest.

        ``max_retries`` means additional retries after the first attempt. When
        resuming, a destination file is skipped only if it matches a verified
        manifest entry by both size and SHA-256. Untracked existing files are
        never overwritten: they are adopted only when they match the live phone.
        """

        if not serial or "\x00" in serial:
            raise ValueError("يجب تحديد الرقم التسلسلي للهاتف.")
        if device.serial != serial:
            raise ValueError("معلومات الهاتف لا تطابق الرقم التسلسلي المحدد.")

        scan_warnings = list(files.warnings) if isinstance(files, ScanResult) else []
        scan_files = list(files.files if isinstance(files, ScanResult) else files)
        targets = _build_targets(scan_files, Path(backup_directory).resolve())
        backup_dir = Path(backup_directory).resolve()
        backup_dir.mkdir(parents=True, exist_ok=True)
        if not backup_dir.is_dir():
            raise BackupDestinationError("مجلد النسخة الاحتياطية غير صالح.")

        # Ensure the signing key is available before any file is copied. This
        # prevents a successful copy from being left without its required signer.
        key_path = self.signer.key_path
        if _lexically_under(key_path, backup_dir) or _under_directory(
            key_path, backup_dir
        ):
            raise BackupDestinationError(
                "ملف المفتاح الخاص يجب أن يبقى خارج مجلد النسخة الاحتياطية."
            )
        public_key_bytes = self.signer.public_key_bytes(signing_password)

        prior_manifest, prior_entries = self._read_prior_manifest(
            backup_dir, public_key_bytes
        )
        existing_log = backup_dir / _BACKUP_LOG_NAME
        if prior_manifest is None and (
            existing_log.exists() or existing_log.is_symlink()
        ):
            raise BackupDestinationError(
                "يوجد سجل غير مرتبط بنسخة موثقة في مجلد الوجهة؛ لم يتم تعديله."
            )
        stored_serial = (
            hashlib.sha256(serial.encode("utf-8")).hexdigest()
            if hash_serial
            else serial
        )
        if prior_manifest is not None:
            prior_device = prior_manifest.get("device")
            if not isinstance(prior_device, dict) or prior_device.get("serial") != stored_serial:
                raise BackupDestinationError(
                    "مجلد النسخة يحتوي على بيانات لهاتف مختلف؛ اختر مجلداً منفصلاً."
                )

        total_files = len(targets)
        total_bytes = sum(target.scanned_file.size for target in targets)
        processed_bytes = 0
        processed_files = 0
        verified_bytes = 0
        verified_count = 0
        skipped_count = 0
        failed_count = 0
        failed_files: list[dict[str, str]] = []
        cancelled = False
        interrupted = False
        started = time.monotonic()
        merged_entries: dict[str, dict[str, object]] = {
            path: dict(entry) for path, entry in prior_entries.items()
        }

        self._write_log(
            backup_dir,
            "INFO",
            {
                "event": "backup_started",
                "serial": stored_serial,
                "files": total_files,
                "bytes": total_bytes,
            },
        )
        for warning in scan_warnings:
            self._write_log(
                backup_dir,
                "WARNING",
                {
                    "event": "scan_warning",
                    "message_ar": warning.message_ar,
                    "source_id": warning.source_id,
                    "phone_path": warning.phone_path,
                    "detail": warning.detail,
                },
            )

        for index, target in enumerate(targets):
            item = target.scanned_file
            previous_entry = prior_entries.get(item.phone_path)
            self._emit_progress(
                progress_callback,
                total_files,
                index,
                total_bytes,
                processed_bytes,
                verified_bytes,
                verified_count,
                skipped_count,
                failed_count,
                item.phone_path,
                started,
            )

            attempt_started = False
            try:
                self._wait_if_paused(cancel_event, pause_event)
                attempt_started = True
                entry, was_skipped = self._backup_one(
                    serial,
                    item,
                    target,
                    previous_entry,
                    backup_dir,
                    cancel_event,
                    pause_event,
                    reconnect_callback,
                )
                merged_entries[item.phone_path] = entry
                verified_count += 1
                verified_bytes += item.size
                if was_skipped:
                    skipped_count += 1
                self._write_log(
                    backup_dir,
                    "INFO",
                    {
                        "event": "file_verified",
                        "phone_path": item.phone_path,
                        "sha256": entry["sha256"],
                        "method": entry["verification_method"],
                        "skipped": was_skipped,
                    },
                )
            except (FileBackupError, AdbCommandError) as caught:
                exc = (
                    caught
                    if isinstance(caught, FileBackupError)
                    else FileBackupError(
                        "تعذّر قراءة هذا الملف من الهاتف؛ تم تسجيله كفشل والمتابعة مع بقية الملفات.",
                        str(caught),
                    )
                )
                failed_count += 1
                failed_files.append(
                    {"phone_path": item.phone_path, "error": exc.message_ar}
                )
                if not self._preserve_prior_verified_entry(
                    target, previous_entry
                ):
                    merged_entries[item.phone_path] = self._file_entry(
                        item,
                        target.relative_path,
                        sha256=None,
                        method="none",
                        status="failed",
                        error=exc.message_ar,
                    )
                self._write_log(
                    backup_dir,
                    "ERROR",
                    {
                        "event": "file_failed",
                        "phone_path": item.phone_path,
                        "error": exc.message_ar,
                        "details": exc.details,
                    },
                )
            except BackupCancelled:
                cancelled = True
                self._write_log(
                    backup_dir,
                    "INFO",
                    {"event": "backup_cancelled", "phone_path": item.phone_path},
                )
                break
            except AdbError as exc:
                interrupted = True
                failed_count += 1
                failed_files.append(
                    {"phone_path": item.phone_path, "error": exc.message_ar}
                )
                if not self._preserve_prior_verified_entry(target, previous_entry):
                    merged_entries[item.phone_path] = self._file_entry(
                        item,
                        target.relative_path,
                        sha256=None,
                        method="none",
                        status="failed",
                        error=exc.message_ar,
                    )
                self._write_log(
                    backup_dir,
                    "ERROR",
                    {
                        "event": "adb_interrupted",
                        "phone_path": item.phone_path,
                        "error": exc.message_ar,
                    },
                )
                break
            finally:
                if attempt_started:
                    processed_bytes += item.size
                    processed_files += 1

            self._emit_progress(
                progress_callback,
                total_files,
                index + 1,
                total_bytes,
                processed_bytes,
                verified_bytes,
                verified_count,
                skipped_count,
                failed_count,
                None,
                started,
            )

        if cancelled or interrupted:
            for target in targets:
                item = target.scanned_file
                if item.phone_path not in merged_entries:
                    merged_entries[item.phone_path] = self._file_entry(
                        item,
                        target.relative_path,
                        sha256=None,
                        method="none",
                        status="pending",
                    )

        now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        )
        manifest: dict[str, object] = {
            "schema_version": 1,
            "app_version": self.app_version,
            "backup_date": now,
            "device": {
                "model": device.model,
                "android_version": device.android_version,
                "serial": stored_serial,
                "serial_hashed": hash_serial,
            },
            "scan_warnings": [
                {
                    "message_ar": warning.message_ar,
                    "source_id": warning.source_id,
                    "phone_path": warning.phone_path,
                    "detail": warning.detail,
                }
                for warning in scan_warnings
            ],
            "files": sorted(
                merged_entries.values(),
                key=lambda entry: str(entry.get("original_phone_path", "")),
            ),
            "backup_summary": {
                "selected_files": total_files,
                "verified_files": verified_count,
                "failed_files": failed_count,
                "scan_warnings": len(scan_warnings),
                "cancelled": cancelled,
                "interrupted": interrupted,
            },
        }
        manifest_bytes = serialize_manifest(manifest)
        manifest_path = backup_dir / _MANIFEST_NAME
        atomic_write_bytes(manifest_path, manifest_bytes)
        try:
            signature = self.signer.sign_manifest(
                manifest_bytes, backup_dir, password=signing_password
            )
        except SigningError as exc:
            self._write_log(
                backup_dir,
                "ERROR",
                {"event": "manifest_sign_failed", "error": exc.message_ar},
            )
            raise

        self._write_log(
            backup_dir,
            "INFO",
            {
                "event": "backup_finished",
                "verified": verified_count,
                "failed": failed_count,
                "cancelled": cancelled,
                "interrupted": interrupted,
                "manifest_sha256": signature.manifest_sha256,
            },
        )
        self._emit_progress(
            progress_callback,
            total_files,
            processed_files,
            total_bytes,
            processed_bytes,
            verified_bytes,
            verified_count,
            skipped_count,
            failed_count,
            None,
            started,
        )

        return BackupResult(
            backup_directory=backup_dir,
            manifest_path=manifest_path,
            files_total=total_files,
            verified_count=verified_count,
            skipped_count=skipped_count,
            failed_count=failed_count,
            verified_bytes=verified_bytes,
            failed_files=failed_files,
            scan_warnings=scan_warnings,
            cancelled=cancelled,
            interrupted=interrupted,
            manifest=manifest,
            signature=signature,
        )

    def _read_prior_manifest(
        self, backup_directory: Path, local_public_key: bytes
    ) -> tuple[dict[str, object] | None, dict[str, dict[str, object]]]:
        manifest_path = backup_directory / _MANIFEST_NAME
        signature_path = backup_directory / "manifest.sig"
        public_path = backup_directory / "public_key.pem"
        present = (manifest_path.exists(), signature_path.exists(), public_path.exists())
        if not any(present):
            return None, {}
        if not all(present):
            raise BackupDestinationError(
                "مجلد النسخة يحتوي على manifest أو توقيع غير مكتمل؛ لن يتم استبداله تلقائياً."
            )
        try:
            manifest_bytes = manifest_path.read_bytes()
            signature_bytes = signature_path.read_bytes()
            public_key_bytes = public_path.read_bytes()
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BackupDestinationError(
                "تعذّر قراءة manifest السابق؛ لن يتم استبدال بياناته.", str(exc)
            ) from exc
        if not ManifestSigner.verify_manifest(
            manifest_bytes, signature_bytes, public_key_bytes
        ):
            raise BackupDestinationError(
                "توقيع manifest السابق غير صالح؛ لن يتم استئناف النسخ فوق هذه الوجهة."
            )
        if not hmac.compare_digest(public_key_bytes, local_public_key):
            raise BackupDestinationError(
                "النسخة السابقة موقعة بمفتاح مختلف عن مفتاح التطبيق المحلي."
            )
        if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
            raise BackupDestinationError("بنية manifest السابق غير صالحة.")
        entries: dict[str, dict[str, object]] = {}
        for entry in manifest["files"]:
            if not isinstance(entry, dict):
                continue
            phone_path = entry.get("original_phone_path")
            if isinstance(phone_path, str):
                try:
                    normalized = AdbManager.validate_phone_path(phone_path)
                except ValueError:
                    continue
                entries[normalized] = dict(entry)
        return manifest, entries

    def _backup_one(
        self,
        serial: str,
        item: ScannedFile,
        target: _BackupTarget,
        previous_entry: dict[str, object] | None,
        backup_directory: Path,
        cancel_event: threading.Event | None,
        pause_event: threading.Event | None,
        reconnect_callback: Callable[[str, AdbError], bool] | None,
    ) -> tuple[dict[str, object], bool]:
        phone_path = AdbManager.validate_phone_path(item.phone_path)
        self._ensure_safe_parent(target.absolute_path, backup_directory)

        if target.absolute_path.is_symlink():
            raise FileBackupError(
                "يوجد رابط رمزي محلي مكان الملف المطلوب؛ لم يتم استبداله.",
                str(target.absolute_path),
            )
        if target.absolute_path.exists() and not target.absolute_path.is_file():
            raise FileBackupError(
                "مسار الوجهة موجود لكنه ليس ملفاً عادياً؛ لم يتم تغييره.",
                str(target.absolute_path),
            )

        existing_before = target.absolute_path.is_file()
        for attempt in range(self.max_retries + 1):
            self._wait_if_paused(cancel_event, pause_event)
            remote_before = self._remote_stat(
                serial,
                phone_path,
                cancel_event,
                pause_event,
                reconnect_callback,
            )
            if remote_before is not None and remote_before != (
                item.size,
                item.modified_time,
            ):
                raise FileBackupError(
                    "تغيّر حجم الملف أو وقت تعديله بعد الفحص؛ أعد فحص الهاتف قبل النسخ.",
                    phone_path,
                )

            remote_hash = self._remote_sha256(
                serial,
                phone_path,
                cancel_event,
                pause_event,
                reconnect_callback,
            )
            if remote_hash is not None and not _SHA256_RE.fullmatch(remote_hash):
                raise FileBackupError("أعاد الهاتف بصمة SHA-256 غير صالحة.", phone_path)
            if (
                remote_hash is not None
                and existing_before
                and previous_entry is not None
                and self._prior_entry_matches_local(previous_entry, target)
                and hmac.compare_digest(
                    remote_hash, str(previous_entry.get("sha256", ""))
                )
            ):
                # A signed/local match is not enough by itself: query the live
                # phone too, so an update since the previous backup is not
                # silently skipped.
                return dict(previous_entry), True
            if remote_hash is not None and existing_before:
                if self._read_local_if_matches_phone(
                    target, remote_hash, item_size=item.size
                ):
                    return self._file_entry(
                        item,
                        target.relative_path,
                        sha256=remote_hash,
                        method="phone-sha256",
                        status="verified",
                    ), True
                raise FileBackupError(
                    "يوجد ملف مختلف في مجلد الوجهة؛ لم يتم استبداله حفاظاً على البيانات.",
                    str(target.absolute_path),
                )

            temporary_files: list[Path] = []
            try:
                if remote_hash is not None:
                    temp = self._new_part_path(target.absolute_path, "phone-hash")
                    temporary_files.append(temp)
                    self._pull(serial, phone_path, temp, cancel_event, pause_event, reconnect_callback)
                    local_hash = sha256_file(temp)
                    local_size = temp.stat().st_size
                    remote_after = self._remote_stat(
                        serial,
                        phone_path,
                        cancel_event,
                        pause_event,
                        reconnect_callback,
                    )
                    stable = remote_before is None or remote_after is None or remote_before == remote_after
                    if local_hash == remote_hash and local_size == item.size and stable:
                        if existing_before:
                            existing_hash = sha256_file(target.absolute_path)
                            existing_size = target.absolute_path.stat().st_size
                            if existing_hash != remote_hash or existing_size != item.size:
                                raise FileBackupError(
                                    "يوجد ملف مختلف في مجلد الوجهة؛ لم يتم استبداله حفاظاً على البيانات.",
                                    str(target.absolute_path),
                                )
                            return self._file_entry(
                                item,
                                target.relative_path,
                                sha256=remote_hash,
                                method="phone-sha256",
                                status="verified",
                            ), True
                        self._install_new_file(temp, target.absolute_path)
                        return self._file_entry(
                            item,
                            target.relative_path,
                            sha256=remote_hash,
                            method="phone-sha256",
                            status="verified",
                        ), False
                else:
                    first = self._new_part_path(target.absolute_path, "double-pull-a")
                    second = self._new_part_path(target.absolute_path, "double-pull-b")
                    temporary_files.extend((first, second))
                    self._pull(serial, phone_path, first, cancel_event, pause_event, reconnect_callback)
                    first_hash = sha256_file(first)
                    first_size = first.stat().st_size
                    self._pull(serial, phone_path, second, cancel_event, pause_event, reconnect_callback)
                    second_hash = sha256_file(second)
                    second_size = second.stat().st_size
                    remote_after = self._remote_stat(
                        serial,
                        phone_path,
                        cancel_event,
                        pause_event,
                        reconnect_callback,
                    )
                    stable = remote_before is None or remote_after is None or remote_before == remote_after
                    if (
                        first_hash == second_hash
                        and first_size == second_size == item.size
                        and stable
                    ):
                        if existing_before:
                            existing_hash = sha256_file(target.absolute_path)
                            existing_size = target.absolute_path.stat().st_size
                            if existing_hash != first_hash or existing_size != item.size:
                                raise FileBackupError(
                                    "يوجد ملف مختلف في مجلد الوجهة؛ لم يتم استبداله حفاظاً على البيانات.",
                                    str(target.absolute_path),
                                )
                            return self._file_entry(
                                item,
                                target.relative_path,
                                sha256=first_hash,
                                method="verified-by-double-pull",
                                status="verified",
                            ), True
                        self._install_new_file(first, target.absolute_path)
                        return self._file_entry(
                            item,
                            target.relative_path,
                            sha256=first_hash,
                            method="verified-by-double-pull",
                            status="verified",
                        ), False
            finally:
                for temporary in temporary_files:
                    try:
                        temporary.unlink(missing_ok=True)
                    except OSError:
                        pass

            existing_before = existing_before or target.absolute_path.is_file()
            if attempt < self.max_retries:
                time.sleep(min(0.1 * (attempt + 1), 0.5))

        raise FileBackupError(
            f"فشل التحقق من الملف بعد {self.max_retries + 1} محاولات؛ لم يُعتمد الملف.",
            phone_path,
        )

    def _remote_stat(
        self,
        serial: str,
        phone_path: str,
        cancel_event: threading.Event | None,
        pause_event: threading.Event | None,
        reconnect_callback: Callable[[str, AdbError], bool] | None,
    ) -> tuple[int, int] | None:
        return self._call_remote(
            serial,
            lambda: self.adb.remote_stat(serial, phone_path),
            cancel_event,
            pause_event,
            reconnect_callback,
        )

    def _remote_sha256(
        self,
        serial: str,
        phone_path: str,
        cancel_event: threading.Event | None,
        pause_event: threading.Event | None,
        reconnect_callback: Callable[[str, AdbError], bool] | None,
    ) -> str | None:
        return self._call_remote(
            serial,
            lambda: self.adb.remote_sha256(serial, phone_path),
            cancel_event,
            pause_event,
            reconnect_callback,
        )

    def _pull(
        self,
        serial: str,
        phone_path: str,
        target: Path,
        cancel_event: threading.Event | None,
        pause_event: threading.Event | None,
        reconnect_callback: Callable[[str, AdbError], bool] | None,
    ) -> None:
        self._ensure_parent_directories(target.parent)
        self._call_remote(
            serial,
            lambda: self.adb.pull_file(
                serial,
                phone_path,
                target,
                preserve_timestamps=True,
                timeout=self.pull_timeout,
            ),
            cancel_event,
            pause_event,
            reconnect_callback,
        )
        if not target.is_file():
            raise FileBackupError("أمر ADB انتهى دون إنشاء الملف المؤقت.", phone_path)

    @staticmethod
    def _call_remote(
        serial: str,
        operation: Callable[[], object],
        cancel_event: threading.Event | None,
        pause_event: threading.Event | None,
        reconnect_callback: Callable[[str, AdbError], bool] | None,
    ):
        while True:
            BackupEngine._wait_if_paused(cancel_event, pause_event)
            try:
                return operation()
            except AdbCommandError:
                # Per-file errors (for example permission denied) are recorded
                # and the backup continues; a reconnect wait would be misleading.
                raise
            except AdbError as exc:
                if reconnect_callback is None or not reconnect_callback(serial, exc):
                    raise

    @staticmethod
    def _wait_if_paused(
        cancel_event: threading.Event | None,
        pause_event: threading.Event | None,
    ) -> None:
        while pause_event is not None and pause_event.is_set():
            if cancel_event is not None and cancel_event.is_set():
                raise BackupCancelled()
            if cancel_event is not None:
                cancel_event.wait(0.2)
            else:
                time.sleep(0.2)
        if cancel_event is not None and cancel_event.is_set():
            raise BackupCancelled()

    @staticmethod
    def _new_part_path(final_path: Path, label: str) -> Path:
        return final_path.with_name(
            f".{final_path.name}.{label}.{uuid.uuid4().hex}.part"
        )

    @staticmethod
    def _ensure_parent_directories(target_parent: Path) -> None:
        target_parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _ensure_safe_parent(target: Path, backup_directory: Path) -> None:
        relative_parent = target.parent.relative_to(backup_directory)
        current = backup_directory
        for component in relative_parent.parts:
            current = current / component
            if current.is_symlink():
                raise FileBackupError(
                    "يوجد رابط رمزي محلي في مسار الوجهة؛ لم يتم استخدامه.",
                    str(current),
                )
        if not _under_directory(target.parent, backup_directory):
            raise FileBackupError("مسار الوجهة خرج عن مجلد النسخة الاحتياطية.")

    @staticmethod
    def _install_new_file(temporary: Path, target: Path) -> None:
        """Install without replacing a file that appeared during the pull."""

        if target.exists() or target.is_symlink():
            raise FileBackupError(
                "ظهر ملف آخر في مسار الوجهة أثناء النسخ؛ لم يتم استبداله.",
                str(target),
            )
        try:
            # Same-directory hard-link creation is atomic and fails if target
            # exists. The temporary and final names are on the same volume.
            os.link(temporary, target)
        except FileExistsError as exc:
            raise FileBackupError(
                "ظهر ملف آخر في مسار الوجهة أثناء النسخ؛ لم يتم استبداله.",
                str(target),
            ) from exc
        except OSError:
            if target.exists() or target.is_symlink():
                raise FileBackupError(
                    "ظهر ملف آخر في مسار الوجهة أثناء النسخ؛ لم يتم استبداله.",
                    str(target),
                )
            # Some filesystems do not support hard links. Reserve the target
            # with O_EXCL before copying so a concurrent file can never be
            # overwritten (POSIX os.rename would replace it).
            try:
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError as exc:
                raise FileBackupError(
                    "ظهر ملف آخر في مسار الوجهة أثناء النسخ؛ لم يتم استبداله.",
                    str(target),
                ) from exc
            except OSError as exc:
                raise FileBackupError(
                    "تعذّر حجز مسار الوجهة لإنشاء ملف جديد.", str(exc)
                ) from exc
            owned_stat = os.fstat(descriptor)
            try:
                with os.fdopen(descriptor, "wb") as destination, open(
                    temporary, "rb"
                ) as source:
                    shutil.copyfileobj(source, destination, 1024 * 1024)
                    destination.flush()
                    os.fsync(destination.fileno())
            except OSError as exc:
                try:
                    current_stat = os.stat(target, follow_symlinks=False)
                    if (current_stat.st_dev, current_stat.st_ino) == (
                        owned_stat.st_dev,
                        owned_stat.st_ino,
                    ):
                        target.unlink()
                except OSError:
                    pass
                raise FileBackupError(
                    "تعذّر تثبيت الملف بعد حجز مسار الوجهة حصرياً.", str(exc)
                ) from exc
            temporary.unlink(missing_ok=True)
        else:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _file_entry(
        item: ScannedFile,
        relative_path: str,
        *,
        sha256: str | None,
        method: str,
        status: str,
        error: str | None = None,
    ) -> dict[str, object]:
        entry: dict[str, object] = {
            "original_phone_path": item.phone_path,
            "relative_path": relative_path,
            "size": item.size,
            "modified_time": item.modified_time,
            "sha256": sha256,
            "verification_method": method,
            "status": status,
        }
        if error:
            entry["error"] = error
        return entry

    @staticmethod
    def _prior_entry_matches_local(
        previous_entry: dict[str, object] | None,
        target: _BackupTarget,
    ) -> bool:
        if not previous_entry:
            return False
        expected_hash = previous_entry.get("sha256")
        if (
            previous_entry.get("status") != "verified"
            or previous_entry.get("relative_path") != target.relative_path
            or not isinstance(expected_hash, str)
            or not _SHA256_RE.fullmatch(expected_hash)
            or not isinstance(previous_entry.get("size"), int)
            or previous_entry.get("size") != target.scanned_file.size
            or previous_entry.get("modified_time")
            != target.scanned_file.modified_time
        ):
            return False
        try:
            if target.absolute_path.stat().st_size != previous_entry.get("size"):
                return False
            return hmac.compare_digest(sha256_file(target.absolute_path), expected_hash)
        except OSError:
            return False

    @staticmethod
    def _preserve_prior_verified_entry(
        target: _BackupTarget,
        previous_entry: dict[str, object] | None,
    ) -> bool:
        if not previous_entry or previous_entry.get("status") != "verified":
            return False
        expected_hash = previous_entry.get("sha256")
        if not isinstance(expected_hash, str) or not _SHA256_RE.fullmatch(expected_hash):
            return False
        try:
            return (
                target.absolute_path.is_file()
                and target.absolute_path.stat().st_size == previous_entry.get("size")
                and hmac.compare_digest(sha256_file(target.absolute_path), expected_hash)
            )
        except OSError:
            return False

    def _read_local_if_matches_phone(
        self,
        target: _BackupTarget,
        phone_hash: str,
        *,
        item_size: int,
    ) -> bool:
        if not target.absolute_path.is_file() or target.absolute_path.is_symlink():
            return False
        try:
            return (
                target.absolute_path.stat().st_size == item_size
                and hmac.compare_digest(sha256_file(target.absolute_path), phone_hash)
            )
        except OSError:
            return False

    def _write_log(self, backup_directory: Path, level: str, event: dict[str, object]) -> None:
        log_path = backup_directory / _BACKUP_LOG_NAME
        line = {
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "level": level,
            **event,
        }
        encoded = json.dumps(line, ensure_ascii=True, sort_keys=True)
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(log_path, flags, 0o600)
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink > 1:
                os.close(descriptor)
                raise BackupDestinationError(
                    "ملف سجل النسخة ليس ملفاً عادياً مستقلاً؛ لم يتم تعديله.",
                    str(log_path),
                )
            with os.fdopen(
                descriptor, "a", encoding="utf-8", newline="\n"
            ) as stream:
                stream.write(encoded + "\n")
        except BackupDestinationError:
            raise
        except OSError as exc:
            raise BackupDestinationError(
                "تعذّرت كتابة سجل النسخة دون المساس بملفات الوجهة الأخرى.",
                str(exc),
            ) from exc

    @staticmethod
    def _emit_progress(
        callback: Callable[[BackupProgress], None] | None,
        files_total: int,
        files_done: int,
        bytes_total: int,
        bytes_processed: int,
        bytes_verified: int,
        verified_count: int,
        skipped_count: int,
        failed_count: int,
        current_phone_path: str | None,
        started: float,
    ) -> None:
        if callback is None:
            return
        elapsed = max(time.monotonic() - started, 0.001)
        speed = bytes_processed / elapsed
        remaining = max(0, bytes_total - bytes_processed)
        eta = (remaining / speed) if speed > 0 else None
        callback(
            BackupProgress(
                files_total=files_total,
                files_done=files_done,
                bytes_total=bytes_total,
                bytes_processed=min(bytes_processed, bytes_total),
                bytes_verified=bytes_verified,
                verified_count=verified_count,
                skipped_count=skipped_count,
                failed_count=failed_count,
                current_phone_path=current_phone_path,
                speed_bytes_per_second=speed,
                eta_seconds=eta,
            )
        )
