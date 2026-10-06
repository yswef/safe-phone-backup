"""Read-only Android storage discovery and file scanning."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from typing import Iterable, Protocol

from .adb_manager import AdbManager
from .models import (
    MediaCategory,
    RemoteListing,
    ScanResult,
    ScanWarning,
    ScannedFile,
    SourceKind,
    StorageSource,
)


@dataclass(frozen=True)
class _DefaultSource:
    source_id: str
    path: str
    label_en: str
    label_ar: str


# These are user-visible scan roots. WhatsApp sources point directly at their
# Media subtrees, so sibling Databases/Backups folders are never enumerated.
_DEFAULT_DIRECTORIES: tuple[_DefaultSource, ...] = (
    _DefaultSource("dcim", "/sdcard/DCIM", "Camera (DCIM)", "الكاميرا (DCIM)"),
    _DefaultSource("pictures", "/sdcard/Pictures", "Pictures", "الصور"),
    _DefaultSource("movies", "/sdcard/Movies", "Movies", "الفيديوهات"),
    _DefaultSource("download", "/sdcard/Download", "Download", "التنزيلات"),
    _DefaultSource("documents", "/sdcard/Documents", "Documents", "المستندات"),
    _DefaultSource("music", "/sdcard/Music", "Music", "الموسيقى"),
    _DefaultSource("recordings", "/sdcard/Recordings", "Recordings", "التسجيلات"),
    _DefaultSource(
        "whatsapp-legacy",
        "/sdcard/WhatsApp/Media",
        "WhatsApp media (legacy)",
        "وسائط واتساب (المجلد القديم)",
    ),
    _DefaultSource(
        "whatsapp-shared",
        "/sdcard/Android/media/com.whatsapp/WhatsApp/Media",
        "WhatsApp shared media",
        "وسائط واتساب المشتركة",
    ),
    _DefaultSource(
        "telegram-legacy",
        "/sdcard/Telegram",
        "Telegram (legacy folder)",
        "تيليجرام (المجلد القديم)",
    ),
    _DefaultSource(
        "telegram-shared",
        "/sdcard/Android/media/org.telegram.messenger",
        "Telegram shared media",
        "وسائط تيليجرام المشتركة",
    ),
)

_PHOTO_EXTENSIONS = frozenset(
    {
        ".jpg",
        ".jpeg",
        ".jpe",
        ".png",
        ".gif",
        ".bmp",
        ".webp",
        ".heic",
        ".heif",
        ".tif",
        ".tiff",
        ".dng",
        ".raw",
        ".arw",
        ".cr2",
        ".cr3",
        ".nef",
        ".nrw",
        ".orf",
        ".rw2",
        ".pef",
        ".srw",
        ".raf",
        ".avif",
        ".jxl",
    }
)
_VIDEO_EXTENSIONS = frozenset(
    {
        ".mp4",
        ".m4v",
        ".mov",
        ".3gp",
        ".3g2",
        ".3gpp",
        ".3gp2",
        ".avi",
        ".mkv",
        ".webm",
        ".mpg",
        ".mpeg",
        ".mpe",
        ".mpv",
        ".wmv",
        ".flv",
        ".vob",
        ".ts",
        ".m2ts",
        ".mts",
        ".mxf",
        ".ogv",
    }
)
_SD_ROOT_RE = re.compile(r"^/storage/[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}$")
_SD_VOLUME_RE = re.compile(
    r"^(/storage/[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})(?:/.*)?$",
    re.DOTALL,
)
_WHATSAPP_EXCLUDED_RELATIVE_PATHS = (
    ("WhatsApp", "Databases"),
    ("WhatsApp", "Backups"),
    ("Android", "media", "com.whatsapp", "WhatsApp", "Databases"),
    ("Android", "media", "com.whatsapp", "WhatsApp", "Backups"),
)
_EMULATED_VOLUME_RE = re.compile(
    r"^(/storage/emulated/[0-9]+)(?:/.*)?$",
    re.DOTALL,
)


class ReadOnlyScannerAdb(Protocol):
    """Small ADB surface needed by this scanner (also straightforward to mock)."""

    def is_directory(self, serial: str, phone_path: str) -> bool: ...

    def list_sd_card_roots(self, serial: str) -> list[str]: ...

    def list_file_stats(
        self,
        serial: str,
        root_path: str,
        *,
        timeout: float | None = None,
        excluded_paths: tuple[str, ...] | list[str] = (),
    ) -> RemoteListing: ...


class SourceDiscoveryAdb(ReadOnlyScannerAdb, Protocol):
    def list_directories(self, serial: str, phone_path: str) -> list[str]: ...


def classify_file(phone_path: str) -> MediaCategory:
    """Classify a file for scan totals without excluding any file types."""

    extension = posixpath.splitext(phone_path)[1].casefold()
    if extension in _PHOTO_EXTENSIONS:
        return MediaCategory.PHOTO
    if extension in _VIDEO_EXTENSIONS:
        return MediaCategory.VIDEO
    return MediaCategory.OTHER


def _normalize_phone_path(path: str) -> str:
    return AdbManager.validate_phone_path(path)


def _is_within(root: str, candidate: str) -> bool:
    root = posixpath.normpath(root)
    candidate = posixpath.normpath(candidate)
    try:
        return posixpath.commonpath((root, candidate)) == root
    except ValueError:
        return False


def _shared_storage_volume_root(path: str) -> str | None:
    """Return the root of an allowed shared-storage volume, if any."""

    path = _normalize_phone_path(path)
    if path == "/sdcard" or path.startswith("/sdcard/"):
        return "/sdcard"
    match = _EMULATED_VOLUME_RE.fullmatch(path)
    if match:
        return match.group(1)
    match = _SD_VOLUME_RE.fullmatch(path)
    if match:
        return match.group(1)
    return None


def _canonical_volume_root(path: str) -> str:
    """Identify common Android volume roots for stable relative paths."""

    path = _normalize_phone_path(path)
    return _shared_storage_volume_root(path) or path


def _is_android_excluded_path(path: str, volume_root: str) -> bool:
    """Return true when ``path`` is inside Android/data or Android/obb."""

    if not _is_within(volume_root, path):
        return False
    relative = posixpath.relpath(path, volume_root)
    if relative in ("", "."):
        return False
    parts = [part.casefold() for part in relative.split("/")]
    return any(
        parts[index] == "android" and parts[index + 1] in {"data", "obb"}
        for index in range(len(parts) - 1)
    )


def _is_whatsapp_database_or_backup(path: str, volume_root: str) -> bool:
    """Exclude WhatsApp's non-media Databases and Backups trees."""

    if not _is_within(volume_root, path):
        return False
    relative = posixpath.relpath(path, volume_root)
    parts = tuple(part.casefold() for part in relative.split("/"))
    return any(
        parts[: len(prefix)] == tuple(component.casefold() for component in prefix)
        for prefix in _WHATSAPP_EXCLUDED_RELATIVE_PATHS
    )


def _validate_whatsapp_custom_root(path: str, volume_root: str) -> None:
    """Require custom roots inside WhatsApp storage to target Media only."""

    restricted_roots = (
        posixpath.join(volume_root, "WhatsApp"),
        posixpath.join(volume_root, "Android", "media", "com.whatsapp"),
    )
    allowed_media_roots = (
        posixpath.join(volume_root, "WhatsApp", "Media"),
        posixpath.join(
            volume_root, "Android", "media", "com.whatsapp", "WhatsApp", "Media"
        ),
    )
    if any(_is_within(root, path) for root in restricted_roots) and not any(
        _is_within(media_root, path) for media_root in allowed_media_roots
    ):
        raise ValueError(
            "مجلد واتساب المخصص يجب أن يكون داخل Media؛ "
            "مجلدا Databases وBackups مستبعدان."
        )


def custom_source(phone_path: str) -> StorageSource:
    """Create a custom-folder source limited to shared user storage.

    Private Android paths such as ``/data`` are never accepted. A custom root
    inside ``Android/data`` or ``Android/obb`` is refused; if a broader root is
    selected, those subtrees are pruned silently while ``Android/media`` remains
    eligible. Custom WhatsApp roots must point into a ``Media`` subtree, and
    Databases/Backups are pruned from broader shared-storage scans.
    """

    path = _normalize_phone_path(phone_path)
    volume_root = _shared_storage_volume_root(path)
    if volume_root is None:
        raise ValueError(
            "المجلد المخصص يجب أن يكون داخل وحدة تخزين مشتركة مثل /sdcard أو بطاقة SD."
        )
    if path == volume_root:
        raise ValueError(
            "اختر مصدر وحدة التخزين بالكامل من القائمة بدلاً من إضافته كمجلد مخصص."
        )
    if _is_android_excluded_path(path, volume_root):
        raise ValueError(
            "تم استبعاد Android/data وAndroid/obb من النسخ الاحتياطي."
        )
    if _is_whatsapp_database_or_backup(path, volume_root):
        raise ValueError("مجلدا WhatsApp Databases وBackups مستبعدان.")
    _validate_whatsapp_custom_root(path, volume_root)
    return StorageSource(
        source_id=f"custom:{path}",
        root_path=path,
        label_en=f"Custom folder: {path}",
        label_ar=f"مجلد مخصص: {path}",
        kind=SourceKind.CUSTOM,
        volume_root=volume_root,
    )


def discover_sources(adb: SourceDiscoveryAdb, serial: str) -> list[StorageSource]:
    """Discover common folders, complete internal storage, and SD-card roots.

    Only existing directories are returned. Android's internal storage is
    offered as the broad ``/sdcard`` choice as well as the common subfolders.
    Removable cards are detected from mounted ``/storage/XXXX-XXXX`` roots.
    """

    sources: list[StorageSource] = []
    known_paths: set[str] = set()

    def add_if_present(source: StorageSource) -> None:
        path = _normalize_phone_path(source.root_path)
        if path in known_paths:
            return
        if adb.is_directory(serial, path):
            known_paths.add(path)
            sources.append(source)

    add_if_present(
        StorageSource(
            source_id="internal:entire",
            root_path="/sdcard",
            label_en="Entire internal storage (/sdcard)",
            label_ar="وحدة التخزين الداخلية بالكامل (/sdcard)",
            kind=SourceKind.INTERNAL_STORAGE,
            volume_root="/sdcard",
        )
    )

    for definition in _DEFAULT_DIRECTORIES:
        add_if_present(
            StorageSource(
                source_id=f"folder:{definition.source_id}",
                root_path=definition.path,
                label_en=definition.label_en,
                label_ar=definition.label_ar,
                kind=SourceKind.DIRECTORY,
                volume_root="/sdcard",
            )
        )

    # list_sd_card_roots already applies the exact XXXX-XXXX convention; keep
    # this second validation to guard against malformed responses from a mock or
    # future ADB implementation.
    for root in adb.list_sd_card_roots(serial):
        normalized_root = _normalize_phone_path(root)
        if not _SD_ROOT_RE.fullmatch(normalized_root):
            continue
        add_if_present(
            StorageSource(
                source_id=f"sd:{normalized_root.rsplit('/', 1)[-1].casefold()}",
                root_path=normalized_root,
                label_en=f"SD card ({normalized_root.rsplit('/', 1)[-1]})",
                label_ar=f"بطاقة SD ({normalized_root.rsplit('/', 1)[-1]})",
                kind=SourceKind.SD_CARD,
                volume_root=normalized_root,
                removable=True,
            )
        )

    return sources


def _relative_to_volume(file_path: str, source: StorageSource) -> str:
    volume_root = source.volume_root or _canonical_volume_root(source.root_path)
    volume_root = _normalize_phone_path(volume_root)
    if _is_within(volume_root, file_path):
        relative = posixpath.relpath(file_path, volume_root)
    else:
        # A defensive fallback for an unusual mount alias; source containment
        # is checked separately before this helper is called.
        relative = posixpath.relpath(file_path, source.root_path)
    if relative in ("", ".") or relative == ".." or relative.startswith("../"):
        raise ValueError("تعذّر تكوين مسار نسبي آمن للملف.")
    return relative


def scan_sources(
    adb: ReadOnlyScannerAdb,
    serial: str,
    sources: Iterable[StorageSource],
    *,
    scan_timeout: float = 300.0,
) -> ScanResult:
    """Recursively scan selected roots and return file totals.

    The scanner only lists regular files and reads their size/mtime. It does not
    hash, pull, alter, or delete anything on the phone. Overlapping source
    selections are de-duplicated by absolute phone path.
    """

    if scan_timeout <= 0:
        raise ValueError("scan_timeout must be greater than zero")

    result = ScanResult()
    seen_source_ids: set[str] = set()
    seen_paths: set[str] = set()

    for source in sources:
        try:
            root = _normalize_phone_path(source.root_path)
        except ValueError as exc:
            result.warnings.append(
                ScanWarning(
                    message_ar="تم تجاهل مجلد بمسار غير صالح.",
                    source_id=source.source_id,
                    detail=str(exc),
                )
            )
            continue

        if source.source_id in seen_source_ids:
            result.warnings.append(
                ScanWarning(
                    message_ar="تم تجاهل مصدر تخزين مكرر.",
                    source_id=source.source_id,
                )
            )
            continue
        seen_source_ids.add(source.source_id)

        try:
            volume_root = _normalize_phone_path(
                source.volume_root or _canonical_volume_root(root)
            )
        except ValueError as exc:
            result.warnings.append(
                ScanWarning(
                    message_ar="تم تجاهل مصدر تخزين بجذر وحدة غير صالح.",
                    source_id=source.source_id,
                    phone_path=root,
                    detail=str(exc),
                )
            )
            continue
        expected_volume = _shared_storage_volume_root(root)
        if (
            not _is_within(volume_root, root)
            or (expected_volume is not None and volume_root != expected_volume)
        ):
            result.warnings.append(
                ScanWarning(
                    message_ar="تم تجاهل مصدر لا يطابق جذر وحدة التخزين.",
                    source_id=source.source_id,
                    phone_path=root,
                )
            )
            continue

        # If a user somehow selects a path inside these excluded trees, skip it
        # without probing it or producing misleading permission-error entries.
        if _is_android_excluded_path(root, volume_root) or (
            _is_whatsapp_database_or_backup(root, volume_root)
        ):
            continue

        if source.kind is SourceKind.CUSTOM:
            try:
                custom_source(root)
            except ValueError as exc:
                result.warnings.append(
                    ScanWarning(
                        message_ar="تم رفض المجلد المخصص لأنه خارج التخزين المشترك.",
                        source_id=source.source_id,
                        phone_path=root,
                        detail=str(exc),
                    )
                )
                continue

        if not adb.is_directory(serial, root):
            result.warnings.append(
                ScanWarning(
                    message_ar="المجلد المحدد غير موجود أو لا يمكن الوصول إليه.",
                    source_id=source.source_id,
                    phone_path=root,
                )
            )
            continue

        # Prune data/obb on-device before find descends into them; because they
        # are never enumerated, permission errors from those trees stay silent.
        excluded_paths = tuple(
            dict.fromkeys(
                excluded_path
                for excluded_path in (
                    posixpath.join(volume_root, "Android", "data"),
                    posixpath.join(volume_root, "Android", "obb"),
                    *(
                        posixpath.join(volume_root, *relative_parts)
                        for relative_parts in _WHATSAPP_EXCLUDED_RELATIVE_PATHS
                    ),
                )
                if excluded_path != root and _is_within(root, excluded_path)
            )
        )

        # Do not turn an ADB disconnection/timeout into an apparent empty scan:
        # transport exceptions intentionally propagate to the caller.
        listing = adb.list_file_stats(
            serial,
            root,
            timeout=scan_timeout,
            excluded_paths=excluded_paths,
        )

        result.sources_scanned.append(source.source_id)
        for detail in listing.warnings:
            result.warnings.append(
                ScanWarning(
                    message_ar="حدثت مشكلة أثناء استكشاف المجلد؛ قد تكون بعض العناصر غير متاحة.",
                    source_id=source.source_id,
                    phone_path=root,
                    detail=detail,
                )
            )
        for issue in listing.issues:
            result.warnings.append(
                ScanWarning(
                    message_ar="تعذّرت قراءة بيانات ملف، لذلك لم يدخل في إجمالي الحجم.",
                    source_id=source.source_id,
                    phone_path=issue.path,
                    detail=issue.message,
                )
            )

        for raw_symlink_path in listing.symlinks:
            try:
                symlink_path = _normalize_phone_path(raw_symlink_path)
            except ValueError as exc:
                result.warnings.append(
                    ScanWarning(
                        message_ar="تم تجاهل رابط رمزي بمسار غير صالح.",
                        source_id=source.source_id,
                        detail=str(exc),
                    )
                )
                continue
            if not _is_within(root, symlink_path):
                result.warnings.append(
                    ScanWarning(
                        message_ar="تم تجاهل رابط رمزي خرج عن المجلد المحدد.",
                        source_id=source.source_id,
                        phone_path=symlink_path,
                    )
                )
                continue
            if _is_android_excluded_path(symlink_path, volume_root) or (
                _is_whatsapp_database_or_backup(symlink_path, volume_root)
            ):
                continue
            result.skipped_symlink_paths.append(symlink_path)
            result.warnings.append(
                ScanWarning(
                    message_ar="تم تخطي رابط رمزي دون اتباع هدفه.",
                    source_id=source.source_id,
                    phone_path=symlink_path,
                )
            )

        for remote_file in listing.files:
            try:
                phone_path = _normalize_phone_path(remote_file.path)
            except ValueError as exc:
                result.warnings.append(
                    ScanWarning(
                        message_ar="تم تجاهل مسار ملف غير صالح أرسله الهاتف.",
                        source_id=source.source_id,
                        detail=str(exc),
                    )
                )
                continue

            if not _is_within(root, phone_path):
                result.warnings.append(
                    ScanWarning(
                        message_ar="تم تجاهل مسار خرج عن المجلد المحدد.",
                        source_id=source.source_id,
                        phone_path=phone_path,
                    )
                )
                continue
            if _is_android_excluded_path(phone_path, volume_root) or (
                _is_whatsapp_database_or_backup(phone_path, volume_root)
            ):
                continue
            if remote_file.size < 0:
                result.warnings.append(
                    ScanWarning(
                        message_ar="تم تجاهل ملف بحجم غير صالح.",
                        source_id=source.source_id,
                        phone_path=phone_path,
                    )
                )
                continue
            if phone_path in seen_paths:
                continue

            try:
                relative_path = _relative_to_volume(phone_path, source)
            except ValueError as exc:
                result.warnings.append(
                    ScanWarning(
                        message_ar="تعذّر إنشاء المسار النسبي الآمن للملف.",
                        source_id=source.source_id,
                        phone_path=phone_path,
                        detail=str(exc),
                    )
                )
                continue

            seen_paths.add(phone_path)
            result.files.append(
                ScannedFile(
                    phone_path=phone_path,
                    relative_path=relative_path,
                    size=remote_file.size,
                    modified_time=remote_file.modified_time,
                    category=classify_file(phone_path),
                    source_id=source.source_id,
                )
            )

    return result
