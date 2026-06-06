"""JSON loader for local synthetic event samples."""

from __future__ import annotations

import json
from pathlib import Path

from offline_packet_analyzer.loaders.common import event_from_mapping, event_is_malformed
from offline_packet_analyzer.models.load_result import LoadResult
from offline_packet_analyzer.validators import validate_sample_file


def load_json_file(path: Path) -> LoadResult:
    """Load a JSON synthetic sample file."""
    result = LoadResult(input_path=str(path))
    file_errors = validate_sample_file(path)
    if file_errors:
        result.errors.extend(file_errors)
        return result

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        result.errors.append(f"{path}: malformed JSON: {exc.msg}")
        result.malformed_records += 1
        return result

    if not isinstance(data, list):
        result.errors.append(f"{path}: expected a JSON array of records")
        result.malformed_records += 1
        return result

    result.files_loaded.append(str(path))
    for index, item in enumerate(data):
        result.records_seen += 1
        if not isinstance(item, dict):
            result.errors.append(f"{path}: record {index} is not an object")
            result.malformed_records += 1
            continue

        event = event_from_mapping(path, index, item)
        result.events.append(event)
        if event_is_malformed(event):
            result.malformed_records += 1

    return result
