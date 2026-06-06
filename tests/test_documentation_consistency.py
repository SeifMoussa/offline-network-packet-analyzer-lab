import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_docs_check_script_exists_and_passes() -> None:
    script = ROOT / "scripts" / "check-docs.py"
    spec = importlib.util.spec_from_file_location("check_docs", script)

    assert script.exists()
    assert spec is not None
    assert spec.loader is not None
    check_docs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check_docs)
    assert check_docs.main() == 0


def test_docs_are_honest_about_ci_codeql_verification_status() -> None:
    content = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [
            ROOT / "README.md",
            ROOT / "TESTING_REPORT.md",
            ROOT / "PROJECT_COMPLETION_CHECKLIST.md",
            ROOT / "CHANGELOG.md",
        ]
    ).lower()

    assert "ci/codeql configured but not yet github-verified" in content
    assert "github actions passed" not in content
    assert "codeql passed" not in content
    assert "repository has been published" not in content
    assert "release has been created" not in content


def test_readme_future_badges_use_expected_repository_path() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "SeifMoussa/offline-network-packet-analyzer-lab/actions/workflows/ci.yml" in readme
    assert "SeifMoussa/offline-network-packet-analyzer-lab/actions/workflows/codeql.yml" in readme
    assert "SeifMoussa/offline-network-packet-analyzer-lab/blob/main/LICENSE" in readme
