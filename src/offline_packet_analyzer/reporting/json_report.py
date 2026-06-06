"""JSON report generation."""

from __future__ import annotations

import json
from typing import Any


def generate_json_report(report_data: dict[str, Any]) -> str:
    """Generate a stable JSON report string."""
    return json.dumps(report_data, indent=2, sort_keys=True) + "\n"
