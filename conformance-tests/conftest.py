"""Reuse SDK fixtures and generate conformance execution reports.

Tests are mapped to catalog case IDs via the ``@pytest.mark.conformance``
marker instead of an external mapping file::

    @pytest.mark.conformance("rfc9068-valid-at-jwt-must-verify")
    async def test_rfc9068_valid_at_jwt_must_verify(...):
        ...

Optional coverage metadata can be added::

    @pytest.mark.conformance(
        "rfc9449-dpop-proof-jwk-must-not-include-private-key-material",
        level="partial",
        gaps=["expected.error_hint"],
        note="Python rejects the proof but does not expose a stable diagnostic.",
    )
    async def test_...(...):
        ...

Tests that are not yet implemented should use ``pytest.xfail``::

    @pytest.mark.conformance("rfc9449-dpop-inbound-nonce-must-be-validated-when-required")
    async def test_...(...):
        pytest.xfail("Not implemented: inbound nonce enforcement")
"""

import json
import os
import re
from datetime import UTC, datetime
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Any

import authplane

_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_CATALOG_PATH = _ROOT.parent / "conformance" / "oauth-sdk-conformance-catalog.yaml"
_CATALOG_PATH = (
    Path(os.environ["CONFORMANCE_CATALOG_PATH"])
    if "CONFORMANCE_CATALOG_PATH" in os.environ
    else Path(os.environ["AUTHPLANE_CONFORMANCE_CATALOG"])
    if "AUTHPLANE_CONFORMANCE_CATALOG" in os.environ
    else _DEFAULT_CATALOG_PATH
)
_REPORT_PATH = _ROOT / "conformance-report.json"
_REPORT_MD_PATH = _ROOT / "conformance-report.md"
_SOURCE = _ROOT / "tests" / "conftest.py"
_SPEC = spec_from_file_location("authplane_sdk_tests_conftest", _SOURCE)
if _SPEC is None or _SPEC.loader is None:  # pragma: no cover - defensive import guard
    raise RuntimeError(f"Unable to load fixtures from {_SOURCE}")
_MODULE = module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)

_catalog_version = ""
_catalog_ids: list[str] = []
_results: dict[str, dict[str, Any]] = {}
_uncatalogued_results: dict[str, dict[str, Any]] = {}

jwks_keypair = _MODULE.jwks_keypair
token_factory = _MODULE.token_factory
mock_jwks = _MODULE.mock_jwks
mock_as_metadata = _MODULE.mock_as_metadata
client = _MODULE.client
verifier = _MODULE.verifier
client_with_discovery = _MODULE.client_with_discovery
verifier_with_discovery = _MODULE.verifier_with_discovery


def _load_catalog_metadata() -> tuple[str, list[str]]:
    text = _CATALOG_PATH.read_text(encoding="utf-8")
    version_match = re.search(r'^catalog_version:\s*"([^"]+)"\s*$', text, flags=re.MULTILINE)
    if version_match is None:  # pragma: no cover - defensive guard
        raise RuntimeError(f"Unable to locate catalog_version in {_CATALOG_PATH}")
    catalog_ids = re.findall(
        r'^\s+- id: "([^"]+)"\s*$', text.split("cases:", 1)[1], flags=re.MULTILINE
    )
    return version_match.group(1), catalog_ids


def _extract_conformance_marker(item: Any) -> tuple[str | None, dict[str, Any]]:
    """Extract case_id and coverage metadata from @pytest.mark.conformance."""
    marker = item.get_closest_marker("conformance")
    if marker is None:
        return None, {}
    case_id = marker.args[0] if marker.args else None
    coverage: dict[str, Any] = {}
    level = marker.kwargs.get("level", "full")
    if level != "full":
        coverage["level"] = level
    gaps = marker.kwargs.get("gaps")
    if gaps:
        coverage["gaps"] = list(gaps)
    note = marker.kwargs.get("note")
    if note:
        coverage["note"] = note
    return case_id, coverage


def _extract_failure_details(report: Any) -> dict[str, Any]:
    details: dict[str, Any] = {}
    longrepr = getattr(report, "longrepr", None)
    crash = getattr(longrepr, "reprcrash", None)
    if crash is not None:
        details["path"] = str(getattr(crash, "path", ""))
        details["line"] = getattr(crash, "lineno", None)
        details["message"] = str(getattr(crash, "message", ""))
    text = str(longrepr) if longrepr is not None else ""
    if text:
        details["longrepr"] = text
    return details


def _build_markdown_report(payload: dict[str, Any]) -> str:
    implementation = payload["implementation"]
    summary = payload["summary"]
    uncatalogued_summary = payload["uncatalogued_summary"]
    lines = [
        "# Conformance Report",
        "",
        f"- Catalog: `{payload['catalog_id']}` `{payload['catalog_version']}`",
        f"- Implementation: `{implementation['name']}` `{implementation['version']}`",
        f"- Language: `{implementation['language']}`",
        f"- Generated: `{payload['generated_at']}`",
        f"- Runner: `{payload['runner']['tool']}` exit status `{payload['runner']['exit_status']}`",
        "",
        "## Summary",
        "",
        f"- Total: `{summary['total']}`",
        f"- Passed: `{summary['passed']}`",
        f"- Failed: `{summary['failed']}`",
        f"- Skipped: `{summary['skipped']}`",
        f"- Not run: `{summary['not_run']}`",
        "",
        "## Uncatalogued Suite Tests",
        "",
        f"- Total: `{uncatalogued_summary['total']}`",
        f"- Passed: `{uncatalogued_summary['passed']}`",
        f"- Failed: `{uncatalogued_summary['failed']}`",
        f"- Skipped: `{uncatalogued_summary['skipped']}`",
        f"- Not run: `{uncatalogued_summary['not_run']}`",
        "",
        "## Cases",
        "",
        "| Case ID | Status | Coverage | Phase | Note |",
        "|---|---|---|---|---|",
    ]
    for case in payload["cases"]:
        coverage = case.get("coverage", {})
        level = coverage.get("level", "full") if coverage else ""
        note = coverage.get("note", "")
        lines.append(
            f"| `{case['case_id']}` | `{case['status']}` | `{level}` | `{case.get('phase', '')}` | {note} |"
        )

    failures = [case for case in payload["cases"] if case["status"] == "failed"]
    if failures:
        lines.extend(["", "## Failures", ""])
        for case in failures:
            lines.append(f"### `{case['case_id']}`")
            failure = case.get("failure", {})
            message = failure.get("message") or "No failure message captured."
            lines.append("")
            lines.append(f"- Message: {message}")
            if failure.get("path"):
                lines.append(f"- Path: `{failure['path']}`")
            if failure.get("line") is not None:
                lines.append(f"- Line: `{failure['line']}`")
            if failure.get("longrepr"):
                lines.extend(["", "```text", failure["longrepr"], "```"])
            lines.append("")

    coverage_notes = [case for case in payload["cases"] if case.get("coverage", {}).get("note")]
    if coverage_notes:
        lines.extend(["", "## Coverage Notes", ""])
        for case in coverage_notes:
            cov = case["coverage"]
            lines.append(f"### `{case['case_id']}`")
            lines.append("")
            lines.append(f"- Level: `{cov.get('level', 'full')}`")
            if cov.get("gaps"):
                lines.append(f"- Gaps: {', '.join(f'`{g}`' for g in cov['gaps'])}")
            lines.append(f"- Note: {cov['note']}")
            lines.append("")

    uncatalogued = payload.get("uncatalogued_tests", [])
    if uncatalogued:
        lines.extend(
            ["", "## Uncatalogued Test Details", "", "| Test | Status | Phase |", "|---|---|---|"]
        )
        for test in uncatalogued:
            lines.append(f"| `{test['nodeid']}` | `{test['status']}` | `{test.get('phase', '')}` |")

    return "\n".join(lines).rstrip() + "\n"


def _update_result_entry(entry: dict[str, Any], report: Any) -> None:
    if report.when == "setup" and report.failed:
        entry["status"] = "failed"
        entry["phase"] = "setup"
        entry["failure"] = _extract_failure_details(report)
    elif report.when == "setup" and report.skipped:
        entry["status"] = "skipped"
        entry["phase"] = "setup"
    elif report.when == "call":
        entry["phase"] = "call"
        if report.passed:
            entry["status"] = "passed"
        elif report.failed:
            entry["status"] = "failed"
            entry["failure"] = _extract_failure_details(report)
        elif report.skipped:
            entry["status"] = "skipped"
    elif report.when == "teardown" and report.failed and entry.get("status") != "failed":
        entry["status"] = "failed"
        entry["phase"] = "teardown"
        entry["failure"] = _extract_failure_details(report)


# -- Marker-to-case-id index built during collection --------------------------

_ITEM_CASE_MAP: dict[str, tuple[str | None, dict[str, Any]]] = {}


def pytest_configure(config: Any) -> None:
    config.addinivalue_line(
        "markers", "conformance(case_id, *, level, gaps, note): map test to catalog case"
    )
    global _catalog_version, _catalog_ids, _results, _uncatalogued_results
    _catalog_version, _catalog_ids = _load_catalog_metadata()
    _results = {}
    _uncatalogued_results = {}


def pytest_collection_modifyitems(items: list[Any]) -> None:
    """Build the case-id index from markers after collection."""
    for item in items:
        case_id, coverage = _extract_conformance_marker(item)
        _ITEM_CASE_MAP[item.nodeid] = (case_id, coverage)


def pytest_runtest_logreport(report: Any) -> None:
    case_id, coverage = _ITEM_CASE_MAP.get(report.nodeid, (None, {}))
    if case_id is not None:
        entry = _results.setdefault(
            case_id,
            {
                "case_id": case_id,
                "nodeid": report.nodeid,
                "status": "not_run",
                "coverage": coverage,
            },
        )
        _update_result_entry(entry, report)
        return

    entry = _uncatalogued_results.setdefault(
        report.nodeid,
        {
            "nodeid": report.nodeid,
            "status": "not_run",
        },
    )
    _update_result_entry(entry, report)


def pytest_sessionfinish(session: Any, exitstatus: int) -> None:
    report_cases: list[dict[str, Any]] = []
    for case_id in _catalog_ids:
        report_cases.append(_results.get(case_id, {"case_id": case_id, "status": "not_run"}))

    summary = {
        "passed": sum(1 for case in report_cases if case["status"] == "passed"),
        "failed": sum(1 for case in report_cases if case["status"] == "failed"),
        "skipped": sum(1 for case in report_cases if case["status"] == "skipped"),
        "not_run": sum(1 for case in report_cases if case["status"] == "not_run"),
        "total": len(report_cases),
    }
    uncatalogued_tests = list(_uncatalogued_results.values())
    uncatalogued_summary = {
        "passed": sum(1 for test in uncatalogued_tests if test["status"] == "passed"),
        "failed": sum(1 for test in uncatalogued_tests if test["status"] == "failed"),
        "skipped": sum(1 for test in uncatalogued_tests if test["status"] == "skipped"),
        "not_run": sum(1 for test in uncatalogued_tests if test["status"] == "not_run"),
        "total": len(uncatalogued_tests),
    }

    payload = {
        "catalog_id": "oauth-sdk-conformance-catalog",
        "catalog_version": _catalog_version,
        "generated_at": datetime.now(UTC).isoformat(),
        "implementation": {
            "name": "authplane-python-sdk",
            "language": "python",
            "version": authplane.__version__,
            "root": str(_ROOT),
        },
        "runner": {
            "tool": "pytest",
            "exit_status": exitstatus,
        },
        "summary": summary,
        "uncatalogued_summary": uncatalogued_summary,
        "cases": report_cases,
        "uncatalogued_tests": uncatalogued_tests,
    }
    del session
    _REPORT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _REPORT_MD_PATH.write_text(_build_markdown_report(payload), encoding="utf-8")
