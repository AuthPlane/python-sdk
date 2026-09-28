"""One reader for the shared conformance catalog.

``conftest.py`` builds the conformance report by iterating the catalog's case
ids, and ``test_catalog_alignment.py`` asserts that those ids and the suite's
``@pytest.mark.conformance`` markers agree in both directions. That assertion is
only worth anything if the two are reading the *same* mapping — otherwise the
test certifies a catalog the report never saw.

They used to be separate copies held together by a docstring saying "resolve the
catalog the same way conftest does", and had already drifted three ways: one
used ``partition`` and the other ``split(...)[1]``, one returned a ``set`` and
the other a ``list``, and only one carried the empty-parse guard. This module is
the single copy, so the agreement is structural rather than asserted in prose.

Importing ``conftest`` from a test module is not an alternative: pytest has
already loaded it under its own module name, and a second import re-runs its
module-level fixture setup.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]

# Default layout: python-sdk and conformance cloned as siblings (see README
# `Catalog path` section). Contributors with a different layout override via
# AUTHPLANE_CONFORMANCE_CATALOG.
_DEFAULT_CATALOG_PATH = _ROOT.parent / "conformance" / "oauth-sdk-conformance-catalog.yaml"

_CATALOG_CASE_ID_RE = re.compile(r'^\s+- id: "([^"]+)"\s*$', re.MULTILINE)
_CATALOG_VERSION_RE = re.compile(r'^catalog_version:\s*"([^"]+)"\s*$', re.MULTILINE)


def catalog_path() -> Path:
    """The catalog this suite reads, honouring the environment override."""
    override = os.environ.get("AUTHPLANE_CONFORMANCE_CATALOG")
    return Path(override) if override else _DEFAULT_CATALOG_PATH


def catalog_path_is_explicit() -> bool:
    """Whether the path came from the environment rather than the default layout."""
    return "AUTHPLANE_CONFORMANCE_CATALOG" in os.environ


def load_catalog_case_ids(path: Path | None = None) -> set[str]:
    """Every case id under ``cases:``.

    Raises ``AssertionError`` naming the file when the parse yields nothing. A
    catalog that parsed to nothing passes the coverage direction vacuously and
    reports every marker as an orphan — drift-shaped output from what is really
    a broken harness, so it has to say which it is.
    """
    resolved = path or catalog_path()
    text = resolved.read_text(encoding="utf-8")
    # ``partition`` rather than ``split(...)[1]``: a catalog with no ``cases:``
    # key at all is the clearest form of the fault the assert below names, and
    # indexing would raise a bare ``IndexError`` before it could be reached.
    _, separator, cases_text = text.partition("cases:")
    case_ids: set[str] = set(_CATALOG_CASE_ID_RE.findall(cases_text)) if separator else set()
    assert case_ids, (
        f"No case ids parsed out of {resolved}. The catalog failed to parse or the "
        "wrong file was resolved — this is a harness problem, not catalog drift."
    )
    return case_ids


def load_catalog_version(path: Path | None = None) -> str:
    """The ``catalog_version`` string, for the report header."""
    resolved = path or catalog_path()
    text = resolved.read_text(encoding="utf-8")
    match = _CATALOG_VERSION_RE.search(text)
    if match is None:  # pragma: no cover - defensive guard
        raise RuntimeError(f"Unable to locate catalog_version in {resolved}")
    return match.group(1)
