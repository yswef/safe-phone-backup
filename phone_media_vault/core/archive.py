"""Optional AES-256 encrypted ZIP export of a verified backup.

Uses ``pyzipper`` (WinZip AES, readable by 7-Zip/WinRAR). The export is created
in a temporary file, every archived member is re-read and checked against the
signed manifest hash, and only then is the archive renamed into place.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .verifier import MANIFEST_FILE, load_signed_manifest, safe_manifest_path
from .signer import PUBLIC_KEY_FILE, SIGNATURE_FILE


class ArchiveError(RuntimeError):
    def __init__(self, message_ar: str, details: str | None = None) -> None:
        super().__init__(message_ar)
        self.message_ar = message_ar
        self.details = details


@dataclass(frozen=True)
class ArchiveProgress:
    files_total: int
    files_done: int
    current: str | None


@dataclass(frozen=True)
class ArchiveResult:
    archive_path: Path
    files_archived: int
    bytes_archived: int


def _require_pyzipper():
    try:
        import pyzipper  # type: ignore
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise ArchiveError(
            "التصدير المشفّر يتطلب الحزمة pyzipper. ثبّتها بالأمر: pip install pyzipper"
        ) from exc
    return pyzipper


def export_encrypted_archive(
    backup_directory: str | os.PathLike[str],
    archive_path: str | os.PathLike[str],
    password: str,
    *,
    trusted_public_key_bytes: bytes | None = None,
    cancel_event: threading.Event | None = None,
    progress_callback: Callable[[ArchiveProgress], None] | None = None,
) -> ArchiveResult:
    if not password or len(password) < 8:
        raise ArchiveError("كلمة مرور الأرشيف يجب أن تكون 8 أحرف على الأقل.")
    pyzipper = _require_pyzipper()
    backup_dir = Path(backup_directory).resolve()
    target = Path(archive_path).resolve()
    try:
        target.relative_to(backup_dir)
        raise ArchiveError("لا يمكن حفظ الأرشيف داخل مجلد النسخة نفسها.")
    except ValueError:
        pass
    if target.exists():
        raise ArchiveError("ملف الأرشيف موجود مسبقاً؛ اختر اسماً جديداً.")
    manifest, valid, trusted = load_signed_manifest(
        backup_dir, trusted_public_key_bytes=trusted_public_key_bytes
    )
    if not valid or trusted is False:
        raise ArchiveError("توقيع النسخة غير صالح أو غير موثوق؛ لن يتم التصدير.")

    entries = [
        e for e in manifest.get("files", [])
        if isinstance(e, dict) and e.get("status") == "verified"
    ]
    temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.part")
    target.parent.mkdir(parents=True, exist_ok=True)
    archived_bytes = 0
    try:
        with pyzipper.AESZipFile(
            temporary, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
        ) as archive:
            archive.setpassword(password.encode("utf-8"))
            archive.setencryption(pyzipper.WZ_AES, nbits=256)
            for name in (MANIFEST_FILE, SIGNATURE_FILE, PUBLIC_KEY_FILE):
                archive.write(backup_dir / name, arcname=name)
            for index, entry in enumerate(entries):
                if cancel_event is not None and cancel_event.is_set():
                    raise ArchiveError("أُلغي التصدير.")
                relative = str(entry["relative_path"])
                if progress_callback is not None:
                    progress_callback(ArchiveProgress(len(entries), index, relative))
                local = safe_manifest_path(backup_dir, relative)
                archive.write(local, arcname=relative)
                archived_bytes += int(entry.get("size", 0))
        # Re-open and verify every member against the signed hash.
        with pyzipper.AESZipFile(temporary) as archive:
            archive.setpassword(password.encode("utf-8"))
            for entry in entries:
                digest = hashlib.sha256()
                with archive.open(str(entry["relative_path"])) as member:
                    while chunk := member.read(1024 * 1024):
                        digest.update(chunk)
                if not hmac.compare_digest(digest.hexdigest(), str(entry["sha256"]).lower()):
                    raise ArchiveError("فشل التحقق من ملف داخل الأرشيف.", str(entry["relative_path"]))
        os.replace(temporary, target)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    if progress_callback is not None:
        progress_callback(ArchiveProgress(len(entries), len(entries), None))
    return ArchiveResult(target, len(entries), archived_bytes)
