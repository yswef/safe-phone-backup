"""Typed data models shared by the ADB and scanner layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable


class SourceKind(str, Enum):
    """Kind of Android storage source offered to the user."""

    DIRECTORY = "directory"
    INTERNAL_STORAGE = "internal_storage"
    SD_CARD = "sd_card"
    CUSTOM = "custom"


class MediaCategory(str, Enum):
    PHOTO = "photo"
    VIDEO = "video"
    OTHER = "other"


@dataclass(frozen=True)
class DeviceInfo:
    """ADB device row enriched with Android properties when available."""

    serial: str
    state: str
    model: str = "Unknown"
    android_version: str = "Unknown"
    product: str = "Unknown"
    device_name: str = "Unknown"
    transport_id: str | None = None

    @property
    def is_authorized(self) -> bool:
        return self.state == "device"

    @property
    def status_ar(self) -> str:
        return {
            "device": "متصل ومصرّح به",
            "unauthorized": "بانتظار السماح من الهاتف",
            "offline": "غير متصل حالياً",
        }.get(self.state, f"حالة ADB: {self.state}")


@dataclass(frozen=True)
class StorageSource:
    """A selectable directory on the phone.

    ``root_path`` is the folder scanned by the scanner. ``volume_root`` is the
    stable root used to form a phone-style relative path (for example
    ``/sdcard`` or ``/storage/ABCD-1234``). For custom folders, it defaults to
    the custom folder itself unless the scanner can identify its storage root.
    """

    source_id: str
    root_path: str
    label_en: str
    label_ar: str
    kind: SourceKind = SourceKind.DIRECTORY
    volume_root: str | None = None
    removable: bool = False


@dataclass(frozen=True)
class RemoteFileStat:
    """Metadata read from a file on the Android device."""

    path: str
    size: int
    modified_time: int


@dataclass(frozen=True)
class RemoteFileIssue:
    """A remote file that could not be stat'ed during a scan."""

    path: str
    message: str


@dataclass
class RemoteListing:
    """Result of one remote ``find`` operation."""

    files: list[RemoteFileStat] = field(default_factory=list)
    issues: list[RemoteFileIssue] = field(default_factory=list)
    symlinks: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ScannedFile:
    """A file found under a selected source."""

    phone_path: str
    relative_path: str
    size: int
    modified_time: int
    category: MediaCategory
    source_id: str


@dataclass(frozen=True)
class ScanWarning:
    """Non-fatal discovery/scan warning suitable for a later GUI log."""

    message_ar: str
    source_id: str | None = None
    phone_path: str | None = None
    detail: str | None = None


@dataclass
class ScanResult:
    """Files and summary statistics from a read-only scan."""

    files: list[ScannedFile] = field(default_factory=list)
    warnings: list[ScanWarning] = field(default_factory=list)
    sources_scanned: list[str] = field(default_factory=list)
    skipped_symlink_paths: list[str] = field(default_factory=list)

    @property
    def skipped_symlink_count(self) -> int:
        return len(self.skipped_symlink_paths)

    @property
    def total_files(self) -> int:
        return len(self.files)

    @property
    def total_bytes(self) -> int:
        return sum(item.size for item in self.files)

    @property
    def photo_count(self) -> int:
        return sum(item.category is MediaCategory.PHOTO for item in self.files)

    @property
    def video_count(self) -> int:
        return sum(item.category is MediaCategory.VIDEO for item in self.files)

    @property
    def other_count(self) -> int:
        return sum(item.category is MediaCategory.OTHER for item in self.files)

    @property
    def photo_bytes(self) -> int:
        return sum(item.size for item in self.files if item.category is MediaCategory.PHOTO)

    @property
    def video_bytes(self) -> int:
        return sum(item.size for item in self.files if item.category is MediaCategory.VIDEO)

    @property
    def other_bytes(self) -> int:
        return sum(item.size for item in self.files if item.category is MediaCategory.OTHER)

    def extend_files(self, files: Iterable[ScannedFile]) -> None:
        self.files.extend(files)
