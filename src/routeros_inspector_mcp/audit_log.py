"""Audit logging for MCP/service operations.

Every operation is logged to a JSONL file. No secrets or raw sensitive
payloads are written — only metadata and error classes.
"""

from __future__ import annotations

import json
import pathlib
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field


@dataclass
class AuditEntry:
    """Single audit log entry."""

    request_id: str
    timestamp: str  # ISO 8601 UTC
    operation: str
    device_ids: list[str] = field(default_factory=list)
    duration_ms: int = 0
    status: str = "pending"  # pending | success | partial | error
    error_class: str = ""
    artifact_path: str = ""


class AuditLogger:
    """Append-only JSONL audit logger."""

    def __init__(self, log_path: pathlib.Path):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, entry: AuditEntry) -> None:
        """Append an entry to the JSONL log."""
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(entry)) + "\n")

    @contextmanager
    def track(self, operation: str, device_ids: list[str] | None = None):
        """Context manager that tracks operation timing and status."""
        request_id = uuid.uuid4().hex[:16]
        start = time.monotonic()
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        entry = AuditEntry(
            request_id=request_id,
            timestamp=now,
            operation=operation,
            device_ids=device_ids or [],
        )

        try:
            yield request_id
            entry.status = "success"
        except Exception as exc:
            entry.status = "error"
            entry.error_class = exc.__class__.__name__
            raise
        finally:
            elapsed = int((time.monotonic() - start) * 1000)
            entry.duration_ms = elapsed
            self.log(entry)

    def get_entries(self) -> list[AuditEntry]:
        """Read all entries from the log (for testing)."""
        if not self.log_path.exists():
            return []
        entries = []
        for line in self.log_path.read_text().strip().splitlines():
            if line.strip():
                data = json.loads(line)
                entries.append(AuditEntry(**data))
        return entries
