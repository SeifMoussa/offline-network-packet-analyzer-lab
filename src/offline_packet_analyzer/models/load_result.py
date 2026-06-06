"""Load result model for synthetic sample loading."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from offline_packet_analyzer.models.event import PacketEvent


@dataclass(slots=True)
class LoadResult:
    """Summary and records produced by a local sample load."""

    input_path: str
    events: list[PacketEvent] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    files_loaded: list[str] = field(default_factory=list)
    records_seen: int = 0
    malformed_records: int = 0
    skipped_files: list[str] = field(default_factory=list)

    def extend(self, other: LoadResult) -> None:
        """Merge another load result into this result."""
        self.events.extend(other.events)
        self.errors.extend(other.errors)
        self.files_loaded.extend(other.files_loaded)
        self.records_seen += other.records_seen
        self.malformed_records += other.malformed_records
        self.skipped_files.extend(other.skipped_files)

    def to_summary_dict(self) -> dict[str, Any]:
        """Return a stable machine-readable summary."""
        return {
            "input_path": self.input_path,
            "files_loaded": sorted(self.files_loaded),
            "records_seen": self.records_seen,
            "events_loaded": len(self.events),
            "malformed_records": self.malformed_records,
            "skipped_files": sorted(self.skipped_files),
            "errors": self.errors,
        }

    def to_dict(self) -> dict[str, Any]:
        """Return a stable full dictionary representation."""
        data = asdict(self)
        data["events"] = [event.to_dict() for event in self.events]
        data["files_loaded"] = sorted(self.files_loaded)
        data["skipped_files"] = sorted(self.skipped_files)
        return data
