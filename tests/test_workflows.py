from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"
CODEQL_PATH = ROOT / ".github" / "workflows" / "codeql.yml"
DEPENDABOT_PATH = ROOT / ".github" / "dependabot.yml"


def _load_yaml(path: Path) -> dict:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def test_ci_workflow_yaml_parses_and_has_required_jobs() -> None:
    workflow = _load_yaml(CI_PATH)
    jobs = workflow["jobs"]

    assert "tests" in jobs
    assert "docs-safety-checks" in jobs
    assert "cli-smoke" in jobs
    assert jobs["tests"]["name"] == "Tests"
    assert jobs["docs-safety-checks"]["name"] == "Docs Safety Checks"
    assert jobs["cli-smoke"]["name"] == "CLI Smoke"


def test_ci_workflow_triggers_main_and_manual_runs() -> None:
    workflow = _load_yaml(CI_PATH)
    triggers = workflow["on"]

    assert triggers["push"]["branches"] == ["main"]
    assert triggers["pull_request"]["branches"] == ["main"]
    assert "workflow_dispatch" in triggers


def test_ci_uses_python_312_and_coverage_gate() -> None:
    workflow_text = CI_PATH.read_text(encoding="utf-8")

    assert 'python-version: "3.12"' in workflow_text
    assert "--cov=offline_packet_analyzer" in workflow_text
    assert "--cov-fail-under=90" in workflow_text
    assert "python scripts/check-docs.py" in workflow_text


def test_ci_smoke_uses_safe_offline_commands() -> None:
    workflow_text = CI_PATH.read_text(encoding="utf-8")

    assert (
        "python -m offline_packet_analyzer inventory --input samples --format json" in workflow_text
    )
    assert (
        "python -m offline_packet_analyzer detect --input samples --format text "
        "--min-severity medium"
    ) in workflow_text
    assert "--fail-on high" not in workflow_text
    assert "--interface" not in workflow_text
    assert "--pcap" not in workflow_text
    assert "--sniff" not in workflow_text


def test_codeql_workflow_analyzes_python_with_security_quality_queries() -> None:
    workflow = _load_yaml(CODEQL_PATH)
    workflow_text = CODEQL_PATH.read_text(encoding="utf-8")

    assert workflow["jobs"]["analyze"]["name"] == "Analyze Python"
    assert "languages: python" in workflow_text
    assert "queries: security-and-quality" in workflow_text
    assert "github/codeql-action/init@" in workflow_text
    assert "github/codeql-action/analyze@" in workflow_text


def test_codeql_workflow_has_required_triggers() -> None:
    workflow = _load_yaml(CODEQL_PATH)
    triggers = workflow["on"]

    assert triggers["push"]["branches"] == ["main"]
    assert triggers["pull_request"]["branches"] == ["main"]
    assert "schedule" in triggers
    assert "workflow_dispatch" in triggers


def test_dependabot_weekly_for_pip_and_actions_only() -> None:
    config = _load_yaml(DEPENDABOT_PATH)
    updates = config["updates"]
    ecosystems = {item["package-ecosystem"]: item for item in updates}

    assert set(ecosystems) == {"pip", "github-actions"}
    assert ecosystems["pip"]["schedule"]["interval"] == "weekly"
    assert ecosystems["github-actions"]["schedule"]["interval"] == "weekly"
    assert all(item["schedule"]["interval"] != "daily" for item in updates)
    assert "docker" not in ecosystems
