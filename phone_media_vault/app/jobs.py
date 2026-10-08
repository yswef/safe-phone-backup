"""Single-slot background job runner with pause/cancel and polling snapshots."""

from __future__ import annotations

import dataclasses
import threading
import time
import traceback
import uuid
from enum import Enum
from typing import Any, Callable


class JobBusyError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("توجد عملية قيد التشغيل؛ انتظر انتهاءها أو ألغها أولاً.")
        self.message_ar = str(self)


def to_jsonable(value: Any) -> Any:
    """Convert dataclasses/enums/paths into JSON-serializable structures."""

    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


class Job:
    def __init__(self, kind: str) -> None:
        self.id = uuid.uuid4().hex[:12]
        self.kind = kind
        self.state = "running"  # running | paused | done | error | cancelled
        self.progress: dict[str, Any] = {}
        self.result: Any = None
        self.error: str | None = None
        self.error_details: str | None = None
        self.started = time.time()
        self.finished: float | None = None
        self.cancel_event = threading.Event()
        self.pause_event = threading.Event()
        self._lock = threading.Lock()

    def set_progress(self, progress: Any) -> None:
        with self._lock:
            self.progress = to_jsonable(progress)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            state = self.state
            if state == "running" and self.pause_event.is_set():
                state = "paused"
            return {
                "id": self.id,
                "kind": self.kind,
                "state": state,
                "progress": self.progress,
                "result": self.result,
                "error": self.error,
                "error_details": self.error_details,
                "elapsed": (self.finished or time.time()) - self.started,
            }


class JobManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._current: Job | None = None
        self._jobs: dict[str, Job] = {}

    def active(self) -> Job | None:
        with self._lock:
            job = self._current
            return job if job is not None and job.state == "running" else None

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def start(self, kind: str, worker: Callable[[Job], Any]) -> Job:
        with self._lock:
            if self._current is not None and self._current.state == "running":
                raise JobBusyError()
            job = Job(kind)
            self._current = job
            self._jobs[job.id] = job
            # Keep memory bounded.
            if len(self._jobs) > 50:
                for old in list(self._jobs)[:-50]:
                    self._jobs.pop(old, None)

        def run() -> None:
            try:
                result = worker(job)
                with job._lock:
                    job.result = to_jsonable(result)
                    job.state = "cancelled" if job.cancel_event.is_set() and (
                        isinstance(job.result, dict) and job.result.get("cancelled")
                    ) else "done"
            except Exception as exc:  # noqa: BLE001 - surfaced to the UI
                with job._lock:
                    job.error = getattr(exc, "message_ar", None) or str(exc) or exc.__class__.__name__
                    job.error_details = getattr(exc, "details", None) or traceback.format_exc(limit=3)
                    job.state = "cancelled" if job.cancel_event.is_set() else "error"
            finally:
                job.finished = time.time()

        threading.Thread(target=run, name=f"pmv-{kind}-{job.id}", daemon=True).start()
        return job
