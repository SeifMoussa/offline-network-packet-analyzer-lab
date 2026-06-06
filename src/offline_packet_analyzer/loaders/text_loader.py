"""Text loader for local synthetic HTTP-like samples."""

from __future__ import annotations

from pathlib import Path

from offline_packet_analyzer.loaders.common import event_from_mapping, event_is_malformed
from offline_packet_analyzer.models.event import PacketEvent
from offline_packet_analyzer.models.load_result import LoadResult
from offline_packet_analyzer.validators import validate_sample_file


def load_text_file(path: Path) -> LoadResult:
    """Load a whitespace-delimited synthetic HTTP-like sample file."""
    result = LoadResult(input_path=str(path))
    file_errors = validate_sample_file(path)
    if file_errors:
        result.errors.extend(file_errors)
        return result

    result.files_loaded.append(str(path))
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue

        result.records_seen += 1
        parts = line.split()
        if len(parts) != 8:
            result.events.append(
                PacketEvent(
                    source_path=str(path),
                    record_index=index,
                    raw_record=line,
                    parse_status="malformed",
                )
            )
            result.malformed_records += 1
            continue

        timestamp, source_ip, destination_ip, method, host, request_path, user_agent, status = parts
        record = {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "method": method,
            "hostname": host,
            "path": request_path,
            "user_agent": user_agent,
            "status": status,
            "synthetic_marker": True,
        }
        event = event_from_mapping(path, index, record)
        result.events.append(event)
        if event_is_malformed(event):
            result.malformed_records += 1

    return result
