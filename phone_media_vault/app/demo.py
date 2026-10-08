"""A simulated Android phone backed by a local folder (demo mode and tests).

``DemoPhone`` implements the same surface the scanner, backup engine, restore
engine, and safe wipe use, but maps ``/sdcard`` and a fake SD card onto a
temporary directory. It never touches a real device.
"""

from __future__ import annotations

import hashlib
import os
import posixpath
import random
import shutil
import tempfile
from pathlib import Path

from ..core.adb_manager import (
    AdbCommandError,
    AdbManager,
    _PROTECTED_STORAGE_RELATIVE_PATHS,
)
from ..core.adb_writer import validate_writable_phone_path
from ..core.models import DeviceInfo, RemoteFileStat, RemoteListing

DEMO_SERIAL = "DEMO-PHONE-0001"
DEMO_SD = "/storage/1A2B-3C4D"

_SAMPLE_TREE = {
    "DCIM/Camera": [("IMG_2024{:04d}.jpg", 18), ("VID_2024{:04d}.mp4", 4)],
    "Pictures/Screenshots": [("Screenshot_{:04d}.png", 8)],
    "Download": [("document-{:02d}.pdf", 3), ("ملف عربي {:02d}.txt", 2)],
    "WhatsApp/Media/WhatsApp Images": [("IMG-WA{:04d}.jpg", 6)],
    "WhatsApp/Databases": [("msgstore-{:02d}.db.crypt14", 2)],  # must be excluded
    "Android/data/com.example/cache": [("cache-{:02d}.bin", 2)],  # must be excluded
    "Music": [("track {:02d}.mp3", 3)],
}


class DemoPhone:
    """Filesystem-backed fake phone implementing the scanner/backup/restore API."""

    def __init__(self, root: str | os.PathLike[str] | None = None, *, seed: bool = True,
                 sha256_available: bool = True) -> None:
        self.root = Path(root) if root else Path(tempfile.mkdtemp(prefix="pmv-demo-phone-"))
        self.internal = self.root / "internal"
        self.sd = self.root / "sdcard-1A2B-3C4D"
        self.sha256_available = sha256_available
        self.adb_path = "demo"
        self.internal.mkdir(parents=True, exist_ok=True)
        self.sd.mkdir(parents=True, exist_ok=True)
        if seed and not any(self.internal.iterdir()):
            self._seed()

    # ------------------------------------------------------------ seeding
    def _seed(self) -> None:
        rng = random.Random(1234)
        base_time = 1_710_000_000
        for folder, patterns in _SAMPLE_TREE.items():
            directory = self.internal / folder
            directory.mkdir(parents=True, exist_ok=True)
            for pattern, count in patterns:
                for index in range(1, count + 1):
                    path = directory / pattern.format(index)
                    size = rng.randint(2_000, 60_000)
                    path.write_bytes(rng.randbytes(size))
                    stamp = base_time + rng.randint(0, 30_000_000)
                    os.utime(path, (stamp, stamp))
        sd_dir = self.sd / "DCIM" / "Camera"
        sd_dir.mkdir(parents=True, exist_ok=True)
        for index in range(1, 6):
            path = sd_dir / f"SD_IMG_{index:04d}.jpg"
            path.write_bytes(rng.randbytes(rng.randint(5_000, 40_000)))

    # ------------------------------------------------------------ mapping
    def local(self, phone_path: str) -> Path:
        path = AdbManager.validate_phone_path(phone_path)
        for prefix in ("/sdcard", "/storage/emulated/0"):
            if path == prefix or path.startswith(prefix + "/"):
                rest = path[len(prefix):].lstrip("/")
                return self.internal.joinpath(*rest.split("/")) if rest else self.internal
        if path == DEMO_SD or path.startswith(DEMO_SD + "/"):
            rest = path[len(DEMO_SD):].lstrip("/")
            return self.sd.joinpath(*rest.split("/")) if rest else self.sd
        if path == "/storage":
            return self.root
        raise AdbCommandError("المسار غير موجود على الهاتف التجريبي.", path)

    def _phone(self, local: Path, root_phone: str, root_local: Path) -> str:
        relative = local.relative_to(root_local).as_posix()
        return root_phone if relative == "." else posixpath.join(root_phone, relative)

    # ------------------------------------------------------------ devices
    def device(self) -> DeviceInfo:
        return DeviceInfo(serial=DEMO_SERIAL, state="device", model="Demo Phone X",
                          android_version="14", product="demo", device_name="demo")

    def list_devices(self) -> list[DeviceInfo]:
        return [self.device()]

    def resolve_device(self, serial: str | None = None) -> DeviceInfo:
        return self.device()

    def get_device_info(self, serial: str | None = None) -> DeviceInfo:
        return self.device()

    # ------------------------------------------------------------ read ops
    def is_directory(self, serial: str, phone_path: str) -> bool:
        try:
            return self.local(phone_path).is_dir()
        except AdbCommandError:
            return False

    def list_directories(self, serial: str, phone_path: str) -> list[str]:
        if AdbManager.validate_phone_path(phone_path) == "/storage":
            return ["/storage/emulated", "/storage/self", DEMO_SD]
        local = self.local(phone_path)
        return [posixpath.join(phone_path, p.name) for p in sorted(local.iterdir()) if p.is_dir()]

    def list_sd_card_roots(self, serial: str) -> list[str]:
        return [DEMO_SD]

    def list_file_stats(self, serial: str, root_path: str, *, timeout: float | None = None,
                        excluded_paths=()) -> RemoteListing:
        root = AdbManager.validate_phone_path(root_path)
        volume = "/sdcard" if not root.startswith(DEMO_SD) else DEMO_SD
        excluded = set(excluded_paths)
        for parts in _PROTECTED_STORAGE_RELATIVE_PATHS:
            excluded.add(posixpath.join(volume, *parts))
        listing = RemoteListing()
        root_local = self.local(root)
        for current, dirs, files in os.walk(root_local):
            current_phone = self._phone(Path(current), root, root_local)
            dirs[:] = [d for d in sorted(dirs) if posixpath.join(current_phone, d) not in excluded]
            for name in sorted(files):
                local = Path(current) / name
                phone = posixpath.join(current_phone, name)
                if local.is_symlink():
                    listing.symlinks.append(phone)
                    continue
                st = local.stat()
                listing.files.append(RemoteFileStat(phone, st.st_size, int(st.st_mtime)))
        return listing

    def remote_stat(self, serial: str, phone_path: str) -> tuple[int, int] | None:
        local = self.local(phone_path)
        if not local.is_file():
            raise AdbCommandError("تعذّر قراءة بيانات الملف على الهاتف.", phone_path)
        st = local.stat()
        return st.st_size, int(st.st_mtime)

    def remote_sha256(self, serial: str, phone_path: str) -> str | None:
        if not self.sha256_available:
            return None
        local = self.local(phone_path)
        if not local.is_file():
            raise AdbCommandError("تعذّر حساب بصمة الملف على الهاتف.", phone_path)
        return hashlib.sha256(local.read_bytes()).hexdigest()

    def pull_file(self, serial: str, phone_path: str, local_path, *, preserve_timestamps: bool = True,
                  timeout: float | None = None) -> None:
        source = self.local(phone_path)
        if not source.is_file():
            raise AdbCommandError("تعذّر نسخ الملف من الهاتف.", phone_path)
        if preserve_timestamps:
            shutil.copy2(source, local_path)
        else:
            shutil.copyfile(source, local_path)

    # ------------------------------------------------------------ write ops
    def path_exists(self, serial: str, phone_path: str) -> bool:
        local = self.local(phone_path)
        return local.exists() or local.is_symlink()

    def make_directories(self, serial: str, phone_dir: str) -> None:
        self.local(validate_writable_phone_path(phone_dir)).mkdir(parents=True, exist_ok=True)

    def push_file(self, serial: str, local_path, phone_path: str, *, timeout: float | None = None) -> None:
        shutil.copyfile(local_path, self.local(validate_writable_phone_path(phone_path)))

    def rename(self, serial: str, source: str, destination: str) -> None:
        src = self.local(validate_writable_phone_path(source))
        dst = self.local(validate_writable_phone_path(destination))
        if not dst.exists():
            src.rename(dst)

    def set_modified_time(self, serial: str, phone_path: str, epoch_seconds: int) -> bool:
        os.utime(self.local(phone_path), (epoch_seconds, epoch_seconds))
        return True

    def delete_file(self, serial: str, phone_path: str) -> None:
        local = self.local(validate_writable_phone_path(phone_path))
        if not local.is_file() or local.is_symlink():
            raise AdbCommandError("لم يُحذف الملف لأنه ليس ملفاً عادياً على الهاتف.", phone_path)
        local.unlink()

    def media_scan(self, serial: str, phone_path: str) -> None:
        return None
