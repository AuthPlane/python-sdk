#!/usr/bin/env python3
"""Print the conformance case ids this SDK registers, one per line.

This is the repo-specific half of the case-body drift check: the id source
depends on how this repo's harness records registrations, so it lives here and
``conformance-case-body-drift.sh`` stays generic.

The ids come out of ``conformance-report.json``, which ``conformance-tests/
conftest.py`` writes from ``pytest_sessionfinish``. That is the harness's own
record of what registered, so it cannot disagree with what the suite actually
did -- the reason for reading the report rather than grepping
``@pytest.mark.conformance(...)`` out of the test sources, which would be a
second, weaker id extractor that reports what it matched and stays silent about
what it missed.

The report lists one entry per CATALOG case, so presence in it is not
registration. ``nodeid`` is: ``pytest_runtest_logreport`` sets it when a marked
test runs, and the placeholder entries ``pytest_sessionfinish`` synthesizes for
uncovered catalog cases are ``{"case_id": ..., "status": "not_run"}`` with no
``nodeid`` key at all. Reading ``nodeid`` rather than ``status`` matters -- a
registered case whose test failed or skipped is still registered, and still
needs its body watched, but its status is not ``passed``.

Requires the suite to have run, so the report on disk belongs to this commit.

Reading the report with Python rather than jq keeps the consumer in the same
language as the producer: one parse, and every shape guard below phrased against
the structure ``conftest.py`` actually writes.

Inputs (environment):
  CONFORMANCE_REPORT  path to conformance-report.json
                      (default: $GITHUB_WORKSPACE/conformance-report.json)

Exit status:
  0  ids printed on stdout
  1  the report is missing, unreadable, or holds no registered case
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, NoReturn, cast


def fail(message: str) -> NoReturn:
    print(f"::error::{message}", file=sys.stderr)
    raise SystemExit(1)


def as_object(value: Any, what: str) -> dict[str, Any]:
    """Return a decoded JSON value as an object, or fail naming what was read.

    The cast is sound after the isinstance: JSON object keys are always strings.
    """
    if not isinstance(value, dict):
        fail(f"registered case ids: {what} is not a JSON object.")
    return cast("dict[str, Any]", value)


def main() -> None:
    workspace = os.environ.get("GITHUB_WORKSPACE", ".")
    report_path = Path(os.environ.get("CONFORMANCE_REPORT", f"{workspace}/conformance-report.json"))

    if not report_path.is_file():
        fail(
            f"registered case ids: '{report_path}' does not exist. conformance-tests/conftest.py "
            "writes it from pytest_sessionfinish, so either the suite did not run or it failed "
            "before the report was written."
        )

    try:
        decoded: Any = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        fail(f"registered case ids: '{report_path}' could not be read as JSON: {exc}")

    payload = as_object(decoded, f"the top level of '{report_path}'")

    cases: Any = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        fail(f"registered case ids: '{report_path}' has no non-empty 'cases' array.")

    ids: list[str] = []
    for raw_entry in cast("list[Any]", cases):
        entry = as_object(raw_entry, f"a case entry in '{report_path}'")

        # An entry with a case_id that is not a string, or empty, would silently
        # drop out of the filter below and take a real registration with it.
        case_id: Any = entry.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            fail(
                f"registered case ids: '{report_path}' holds a case entry with a missing or "
                "non-string case_id."
            )

        # Absent or empty is the placeholder shape: a catalog case with no
        # marker behind it. Present but not a string is a report this script
        # will not guess at, because the guess would be about which cases stop
        # being guarded.
        nodeid: Any = entry.get("nodeid")
        if nodeid is None or nodeid == "":
            continue
        if not isinstance(nodeid, str):
            fail(
                f"registered case ids: '{report_path}' holds a non-string nodeid on case "
                f"'{case_id}'."
            )
        ids.append(case_id)

    if not ids:
        fail(
            f"registered case ids: '{report_path}' records no case with a nodeid, so no "
            "@pytest.mark.conformance marker registered. Any check restricted to this list "
            "would be vacuously green."
        )

    print("\n".join(ids))


if __name__ == "__main__":
    main()
