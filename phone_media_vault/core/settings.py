"""Persistent user settings and backup history (per-user app data, JSON)."""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path

from .signer import app_data_directory, atomic_write_bytes

SETTINGS_FILE = "settings.json"
HISTORY_FILE = "history.json"
MAX_HISTORY = 200


@dataclass
class Settings:
    default_destination: str = ""
    hash_serial: bool = False
    max_retries: int = 3
    verify_after_backup: bool = True
    restore_conflict_policy: str = "skip"  # skip | rename
    restore_target_folder: str = "/sdcard/Restored"
    media_scan_after_changes: bool = True
    last_selected_sources: list[str] = field(default_factory=list)
    custom_folders: list[str] = field(default_factory=list)

    def validated(self) -> "Settings":
        self.max_retries = max(0, min(10, int(self.max_retries)))
        if self.restore_conflict_policy not in {"skip", "rename"}:
            self.restore_conflict_policy = "skip"
        self.last_selected_sources = [str(s) for s in self.last_selected_sources][:100]
        self.custom_folders = [str(s) for s in self.custom_folders][:50]
        return self


class SettingsStore:
    def __init__(self, directory: str | os.PathLike[str] | None = None) -> None:
        self.directory = Path(directory) if directory is not None else app_data_directory()
        self._lock = threading.Lock()

    @property
    def settings_path(self) -> Path:
        return self.directory / SETTINGS_FILE

    @property
    def history_path(self) -> Path:
        return self.directory / HISTORY_FILE

    def load(self) -> Settings:
        try:
            raw = json.loads(self.settings_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return Settings()
        if not isinstance(raw, dict):
            return Settings()
        known = {f.name for f in fields(Settings)}
        try:
            return Settings(**{k: v for k, v in raw.items() if k in known}).validated()
        except (TypeError, ValueError):
            return Settings()

    def save(self, settings: Settings) -> Settings:
        settings.validated()
        with self._lock:
            atomic_write_bytes(
                self.settings_path,
                json.dumps(asdict(settings), ensure_ascii=False, indent=2).encode("utf-8"),
            )
        return settings

    def update(self, changes: dict[str, object]) -> Settings:
        current = asdict(self.load())
        known = {f.name for f in fields(Settings)}
        current.update({k: v for k, v in changes.items() if k in known})
        return self.save(Settings(**current))

    # ---------------------------------------------------------------- history
    def history(self) -> list[dict[str, object]]:
        try:
            raw = json.loads(self.history_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        return [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []

    def add_history(self, kind: str, **details: object) -> None:
        entry = {
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "kind": kind,
            **details,
        }
        with self._lock:
            items = self.history()
            items.insert(0, entry)
            atomic_write_bytes(
                self.history_path,
                json.dumps(items[:MAX_HISTORY], ensure_ascii=False, indent=2, default=str).encode("utf-8"),
            )
