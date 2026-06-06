"""Inventory and dispatch helpers for local synthetic sample loading."""

from __future__ import annotations

from pathlib import Path

from offline_packet_analyzer.loaders.common import LOADABLE_EXTENSIONS
from offline_packet_analyzer.loaders.csv_loader import load_csv_file
from offline_packet_analyzer.loaders.json_loader import load_json_file
from offline_packet_analyzer.loaders.text_loader import load_text_file
from offline_packet_analyzer.models.load_result import LoadResult
from offline_packet_analyzer.validators import is_relative_to, validate_input_path


def discover_input_files(
    input_path: Path, *, recursive: bool = True
) -> tuple[list[Path], list[str]]:
    """Return loadable files below an explicit local input path."""
    errors = validate_input_path(input_path)
    if errors:
        return [], errors

    resolved = input_path.resolve()
    root = resolved if resolved.is_dir() else resolved.parent

    if resolved.is_file():
        candidates = [resolved]
    elif recursive:
        candidates = [path for path in resolved.rglob("*") if path.is_file()]
    else:
        candidates = [path for path in resolved.iterdir() if path.is_file()]

    files: list[Path] = []
    skipped: list[str] = []
    for candidate in sorted(candidates):
        candidate_resolved = candidate.resolve()
        if not is_relative_to(candidate_resolved, root):
            skipped.append(str(candidate))
            continue
        if candidate_resolved.suffix.lower() in LOADABLE_EXTENSIONS:
            files.append(candidate_resolved)
        else:
            skipped.append(str(candidate_resolved))

    return files, skipped


def load_file(path: Path) -> LoadResult:
    """Dispatch a single local file to the matching loader."""
    suffix = path.suffix.lower()
    if suffix == ".json":
        return load_json_file(path)
    if suffix == ".csv":
        return load_csv_file(path)
    if suffix == ".txt":
        return load_text_file(path)

    result = LoadResult(input_path=str(path))
    result.skipped_files.append(str(path))
    return result


def load_input(input_path: Path, *, recursive: bool = True) -> LoadResult:
    """Load a local file or directory of synthetic samples."""
    result = LoadResult(input_path=str(input_path))
    files, warnings = discover_input_files(input_path, recursive=recursive)

    if warnings and not files:
        result.errors.extend(warnings)
        return result

    result.skipped_files.extend(warnings)
    for path in files:
        result.extend(load_file(path))

    return result
