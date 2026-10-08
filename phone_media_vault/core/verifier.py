"""Offline integrity verification for a signed Phone Media Vault backup.

The verifier never contacts the phone and never modifies the backup. It checks:

* the detached Ed25519 signature over the exact ``manifest.json`` bytes;
* optionally, that the backup public key matches the app's local trust anchor;
* every manifest path is a safe relative path inside the backup folder;
* every ``verified`` file exists, is a regular file, and matches size + SHA-256;
* files present on disk but absent from the manifest (``extra`` files), and
  leftover ``.part`` files from an interrupted run.
"""

from __future__ import annotations

import hmac
import json
import os
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Callable, Iterator

from .backup_engine import sha256_file
from .signer import PUBLIC_KEY_FILE, SIGNATURE_FILE, ManifestSigner

MANIFEST_FILE = "manifest.json"
BACKUP_LOG_FILE = "backup_log.txt"
# Files that the application itself may write at the backup root and that are
# therefore never reported as "extra" untracked files.
RESERVED_ROOT_FILES = frozenset(
    {
        MANIFEST_FILE,
        SIGNATURE_FILE,
        PUBLIC_KEY_FILE,
        BACKUP_LOG_FILE,
        "restore_log.txt",
        "wipe_log.txt",
        "verification_report.html",
        "backup_report.html",
    }
)


class FileStatus(str, Enum):
    OK = "ok"
    MISSING = "missing"
    MODIFIED = "modified"
    SIZE_MISMATCH = "size_mismatch"
    NOT_REGULAR = "not_regular"
    UNSAFE_PATH = "unsafe_path"
    NOT_BACKED_UP = "not_backed_up"  # failed/pending in the manifest itself
    UNREADABLE = "unreadable"


STATUS_LABELS_AR = {
    FileStatus.OK: "سليم",
    FileStatus.MISSING: "مفقود",
    FileStatus.MODIFIED: "معدَّل (البصمة لا تطابق)",
    FileStatus.SIZE_MISMATCH: "الحجم لا يطابق",
    FileStatus.NOT_REGULAR: "ليس ملفاً عادياً",
    FileStatus.UNSAFE_PATH: "مسار غير آمن في manifest",
    FileStatus.NOT_BACKED_UP: "لم يُنسخ (فشل/معلّق في النسخة)",
    FileStatus.UNREADABLE: "تعذّرت قراءته",
}


class VerificationCancelled(RuntimeError):
    def __init__(self) -> None:
        super().__init__("أُلغي التحقق بناءً على طلب المستخدم.")
        self.message_ar = "أُلغي التحقق بناءً على طلب المستخدم."


@dataclass(frozen=True)
class FileCheck:
    phone_path: str
    relative_path: str
    status: FileStatus
    size: int | None = None
    expected_sha256: str | None = None
    actual_sha256: str | None = None
    detail: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is FileStatus.OK

    @property
    def status_ar(self) -> str:
        return STATUS_LABELS_AR[self.status]


@dataclass(frozen=True)
class VerificationProgress:
    files_total: int
    files_done: int
    bytes_total: int
    bytes_done: int
    current_relative_path: str | None


@dataclass
class VerificationReport:
    backup_directory: Path
    manifest_present: bool = False
    signature_valid: bool = False
    public_key_trusted: bool | None = None
    manifest_error: str | None = None
    manifest: dict[str, object] = field(default_factory=dict)
    checks: list[FileCheck] = field(default_factory=list)
    extra_files: list[str] = field(default_factory=list)
    leftover_part_files: list[str] = field(default_factory=list)
    cancelled: bool = False

    # ---- aggregated views -------------------------------------------------
    @property
    def ok_count(self) -> int:
        return sum(check.ok for check in self.checks)

    @property
    def problem_checks(self) -> list[FileCheck]:
        return [check for check in self.checks if not check.ok]

    @property
    def damaged_checks(self) -> list[FileCheck]:
        """Problems with files the manifest claims were verified."""

        return [
            check
            for check in self.checks
            if not check.ok and check.status is not FileStatus.NOT_BACKED_UP
        ]

    @property
    def not_backed_up_count(self) -> int:
        return sum(check.status is FileStatus.NOT_BACKED_UP for check in self.checks)

    @property
    def verified_bytes(self) -> int:
        return sum(check.size or 0 for check in self.checks if check.ok)

    @property
    def intact(self) -> bool:
        """True when signature is valid and every verified file is intact."""

        return (
            self.manifest_present
            and self.signature_valid
            and self.public_key_trusted is not False
            and not self.cancelled
            and self.manifest_error is None
            and not self.damaged_checks
        )

    @property
    def complete(self) -> bool:
        """``intact`` and nothing in the manifest is failed/pending."""

        return self.intact and self.not_backed_up_count == 0 and bool(self.checks)

    @property
    def verdict_ar(self) -> str:
        if not self.manifest_present:
            return "لا توجد نسخة احتياطية موثقة في هذا المجلد."
        if not self.signature_valid:
            return "توقيع manifest غير صالح — قد تكون النسخة معدّلة أو تالفة."
        if self.public_key_trusted is False:
            return "النسخة موقعة بمفتاح غير موثوق على هذا الكمبيوتر."
        if self.manifest_error:
            return f"بنية manifest غير صالحة: {self.manifest_error}"
        if self.cancelled:
            return "أُلغي التحقق قبل اكتماله."
        if self.damaged_checks:
            return f"تم العثور على {len(self.damaged_checks)} ملف تالف أو مفقود."
        if self.not_backed_up_count:
            return (
                "الملفات المنسوخة سليمة، لكن "
                f"{self.not_backed_up_count} ملف لم يُنسخ بنجاح في هذه النسخة."
            )
        return "النسخة الاحتياطية سليمة بالكامل والتوقيع صالح."

    def to_dict(self) -> dict[str, object]:
        device = self.manifest.get("device") if isinstance(self.manifest, dict) else None
        return {
            "backup_directory": str(self.backup_directory),
            "manifest_present": self.manifest_present,
            "signature_valid": self.signature_valid,
            "public_key_trusted": self.public_key_trusted,
            "manifest_error": self.manifest_error,
            "cancelled": self.cancelled,
            "intact": self.intact,
            "complete": self.complete,
            "verdict_ar": self.verdict_ar,
            "backup_date": self.manifest.get("backup_date") if self.manifest else None,
            "device": device if isinstance(device, dict) else None,
            "files_total": len(self.checks),
            "ok_count": self.ok_count,
            "not_backed_up_count": self.not_backed_up_count,
            "damaged_count": len(self.damaged_checks),
            "verified_bytes": self.verified_bytes,
            "extra_files": list(self.extra_files),
            "leftover_part_files": list(self.leftover_part_files),
            "problems": [
                {
                    "phone_path": check.phone_path,
                    "relative_path": check.relative_path,
                    "status": check.status.value,
                    "status_ar": check.status_ar,
                    "detail": check.detail,
                }
                for check in self.problem_checks
            ],
        }


def safe_manifest_path(backup_directory: Path, relative_path: object) -> Path:
    """Resolve a manifest ``relative_path`` and reject traversal/absolute paths."""

    if not isinstance(relative_path, str) or not relative_path:
        raise ValueError("relative_path مفقود أو غير صالح.")
    if "\\" in relative_path or "\x00" in relative_path:
        raise ValueError("relative_path يحتوي على محارف غير مسموحة.")
    relative = PurePosixPath(relative_path)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("relative_path يخرج عن مجلد النسخة.")
    if not relative.parts or relative.parts[0] != "files":
        raise ValueError("relative_path يجب أن يكون داخل المجلد files.")
    if any(":" in part for part in relative.parts):
        raise ValueError("relative_path يحتوي على محرف ':' غير مسموح.")
    destination = backup_directory.joinpath(*relative.parts)
    try:
        destination.resolve(strict=False).relative_to(backup_directory.resolve(strict=False))
    except ValueError as exc:
        raise ValueError("relative_path يخرج عن مجلد النسخة.") from exc
    return destination


def load_signed_manifest(
    backup_directory: str | os.PathLike[str],
    *,
    trusted_public_key_bytes: bytes | None = None,
) -> tuple[dict[str, object], bool, bool | None]:
    """Return ``(manifest, signature_valid, key_trusted)``; raise if absent."""

    backup_dir = Path(backup_directory)
    manifest_bytes = (backup_dir / MANIFEST_FILE).read_bytes()
    try:
        signature_bytes = (backup_dir / SIGNATURE_FILE).read_bytes()
        public_key_bytes = (backup_dir / PUBLIC_KEY_FILE).read_bytes()
    except OSError:
        signature_bytes = b""
        public_key_bytes = b""
    valid = bool(signature_bytes) and ManifestSigner.verify_manifest(
        manifest_bytes, signature_bytes, public_key_bytes
    )
    trusted: bool | None = None
    if trusted_public_key_bytes is not None:
        trusted = bool(public_key_bytes) and hmac.compare_digest(
            public_key_bytes, trusted_public_key_bytes
        )
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("manifest ليس كائناً JSON.")
    return manifest, valid, trusted


def _iter_backup_files(backup_dir: Path) -> Iterator[Path]:
    files_root = backup_dir / "files"
    for root, directories, filenames in os.walk(files_root, followlinks=False):
        directories.sort()
        for name in sorted(filenames):
            yield Path(root) / name
    for entry in sorted(backup_dir.iterdir()) if backup_dir.is_dir() else ():
        if entry.is_file() and entry.name not in RESERVED_ROOT_FILES:
            yield entry


def verify_backup(
    backup_directory: str | os.PathLike[str],
    *,
    trusted_public_key_bytes: bytes | None = None,
    check_hashes: bool = True,
    cancel_event: threading.Event | None = None,
    progress_callback: Callable[[VerificationProgress], None] | None = None,
) -> VerificationReport:
    """Verify signature + every file in a backup folder (read-only)."""

    backup_dir = Path(backup_directory).resolve()
    report = VerificationReport(backup_directory=backup_dir)
    if not (backup_dir / MANIFEST_FILE).is_file():
        return report
    report.manifest_present = True
    try:
        manifest, valid, trusted = load_signed_manifest(
            backup_dir, trusted_public_key_bytes=trusted_public_key_bytes
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        report.manifest_error = str(exc)
        return report
    report.signature_valid = valid
    report.public_key_trusted = trusted
    report.manifest = manifest

    entries = manifest.get("files")
    if not isinstance(entries, list):
        report.manifest_error = "الحقل files مفقود."
        return report

    valid_entries: list[dict[str, object]] = [e for e in entries if isinstance(e, dict)]
    bytes_total = sum(
        int(e["size"]) for e in valid_entries
        if e.get("status") == "verified" and isinstance(e.get("size"), int)
    )
    bytes_done = 0
    tracked: set[str] = set()

    for index, entry in enumerate(valid_entries):
        if cancel_event is not None and cancel_event.is_set():
            report.cancelled = True
            break
        phone_path = str(entry.get("original_phone_path", ""))
        relative_path = str(entry.get("relative_path", ""))
        size = entry.get("size") if isinstance(entry.get("size"), int) else None
        expected = entry.get("sha256") if isinstance(entry.get("sha256"), str) else None
        if progress_callback is not None:
            progress_callback(
                VerificationProgress(len(valid_entries), index, bytes_total, bytes_done, relative_path)
            )
        try:
            local_path = safe_manifest_path(backup_dir, entry.get("relative_path"))
        except ValueError as exc:
            report.checks.append(
                FileCheck(phone_path, relative_path, FileStatus.UNSAFE_PATH, size, expected, detail=str(exc))
            )
            continue
        tracked.add(os.path.normcase(str(local_path)))

        if entry.get("status") != "verified":
            report.checks.append(
                FileCheck(
                    phone_path, relative_path, FileStatus.NOT_BACKED_UP, size, expected,
                    detail=str(entry.get("error") or entry.get("status") or ""),
                )
            )
            continue
        if expected is None or len(expected) != 64 or size is None:
            report.checks.append(
                FileCheck(phone_path, relative_path, FileStatus.UNSAFE_PATH, size, expected,
                          detail="بيانات البصمة أو الحجم مفقودة في manifest.")
            )
            continue
        try:
            if local_path.is_symlink() or (local_path.exists() and not local_path.is_file()):
                status, actual = FileStatus.NOT_REGULAR, None
            elif not local_path.exists():
                status, actual = FileStatus.MISSING, None
            elif local_path.stat().st_size != size:
                status, actual = FileStatus.SIZE_MISMATCH, None
            elif check_hashes:
                actual = sha256_file(local_path)
                status = (
                    FileStatus.OK
                    if hmac.compare_digest(actual, expected.lower())
                    else FileStatus.MODIFIED
                )
            else:
                status, actual = FileStatus.OK, None
        except OSError as exc:
            report.checks.append(
                FileCheck(phone_path, relative_path, FileStatus.UNREADABLE, size, expected, detail=str(exc))
            )
            continue
        bytes_done += size
        report.checks.append(FileCheck(phone_path, relative_path, status, size, expected, actual))

    if not report.cancelled:
        for path in _iter_backup_files(backup_dir):
            normalized = os.path.normcase(str(path))
            if normalized in tracked:
                continue
            relative = path.relative_to(backup_dir).as_posix()
            if path.name.endswith(".part"):
                report.leftover_part_files.append(relative)
            else:
                report.extra_files.append(relative)

    if progress_callback is not None:
        progress_callback(
            VerificationProgress(len(valid_entries), len(report.checks), bytes_total, bytes_done, None)
        )
    return report
