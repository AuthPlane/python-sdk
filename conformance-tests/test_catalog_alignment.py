"""Ensure the catalog and the ``@pytest.mark.conformance`` markers agree.

Both directions are asserted, because each catches a different way the
mapping rots and neither implies the other:

* catalog -> marker: a catalog case nothing claims is a case this SDK does
  not cover, reported as ``not_run`` rather than as a failure.
* marker -> catalog: a marker naming a case the catalog does not carry — a
  typo, a renamed case, a case dropped from the catalog — claims coverage
  that maps to nothing. The report is built by iterating the catalog ids, so
  such a marker is silently dropped: the run stays green and the catalog case
  it was meant to cover is left uncovered while the report says otherwise.

Together they are what makes bumping ``.conformance-catalog-ref`` safe in
both directions: a pin bump without markers goes red on the first, and
markers without a pin bump go red on the second.

The scan is over ``conformance-tests/test_*.py`` source, so a marker on a
deselected or collection-erroring test still counts.
"""

import ast
from pathlib import Path

from _catalog import load_catalog_case_ids

# Marks the two assertions that mean the catalog and the markers disagree, so
# the drift workflow can tell them from a harness fault (an unparseable catalog,
# a collection error) and stop labelling everything "drift detected".
# Deliberately NOT on the harness assert in ``_catalog.load_catalog_case_ids``.
_DRIFT_PREFIX = "Conformance-catalog drift:"


def _collect_conformance_case_ids() -> set[str]:
    """Walk all test files and extract case IDs from @pytest.mark.conformance markers."""
    suite_dir = Path(__file__).resolve().parent
    case_ids: set[str] = set()
    for path in suite_dir.glob("test_*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            # ClassDef too: pytest applies a class-level marker to every test in
            # the class, so a marker there is as real as one on a function. A
            # scan that cannot see it reports the id as uncovered in one
            # direction and misses a bogus id in the other.
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            for decorator in node.decorator_list:
                # Match @pytest.mark.conformance("case-id")
                if not (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr == "conformance"
                    and decorator.args
                ):
                    continue
                first = decorator.args[0]
                # A computed id is invisible to this scan but visible to pytest
                # at runtime — the precise shape of "claims coverage that maps
                # to nothing". Refuse it rather than skip it.
                assert isinstance(first, ast.Constant) and isinstance(first.value, str), (
                    f"{path.name}:{decorator.lineno}: @pytest.mark.conformance needs a literal "
                    "string case id; a computed one cannot be checked against the catalog."
                )
                case_ids.add(first.value)
    return case_ids


def test_catalog_case_ids_are_represented_in_conformance_tests() -> None:
    missing = sorted(load_catalog_case_ids() - _collect_conformance_case_ids())
    assert missing == [], (
        f"{_DRIFT_PREFIX} {len(missing)} catalog case(s) have no @pytest.mark.conformance marker in "
        "conformance-tests/. Add SDK-side coverage for each, then bump "
        f".conformance-catalog-ref: {missing}"
    )


def test_conformance_markers_name_only_catalog_case_ids() -> None:
    unknown = sorted(_collect_conformance_case_ids() - load_catalog_case_ids())
    assert unknown == [], (
        f"{_DRIFT_PREFIX} {len(unknown)} @pytest.mark.conformance marker(s) in conformance-tests/ name a "
        "case id absent from the catalog, so they claim coverage that maps to nothing and "
        "is dropped from the report. Correct the id, drop the marker, or bump "
        f".conformance-catalog-ref to a revision that carries the case: {unknown}"
    )
