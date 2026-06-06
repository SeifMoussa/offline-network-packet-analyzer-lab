"""CSV loader for local synthetic DNS-like samples."""

from __future__ import annotations

import csv
from pathlib import Path

from offline_packet_analyzer.loaders.common import event_from_mapping, event_is_malformed
from offline_packet_analyzer.models.load_result import LoadResult
from offline_packet_analyzer.validators import validate_sample_file


def load_csv_file(path: Path) -> LoadResult:
    """Load a CSV synthetic sample file."""
    result = LoadResult(input_path=str(path))
    file_errors = validate_sample_file(path)
    if file_errors:
        result.errors.extend(file_errors)
        return result

    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
    except csv.Error as exc:
        result.errors.append(f"{path}: malformed CSV: {exc}")
        result.malformed_records += 1
        return result

    result.files_loaded.append(str(path))
    for index, row in enumerate(rows):
        result.records_seen += 1
        normalized = {
            "timestamp": row.get("timestamp"),
            "source_ip": row.get("source_ip"),
            "query_name": row.get("query_name"),
            "status": row.get("response_code"),
            "synthetic_marker": row.get("synthetic_marker") == "true",
        }
        event = event_from_mapping(path, index, normalized)
        result.events.append(event)
        if event_is_malformed(event):
            result.malformed_records += 1

    return result
