"""Ensure every catalog case id is covered by a @pytest.mark.conformance marker."""

import ast
import os
import re
from pathlib import Path


def _collect_conformance_case_ids() -> set[str]:
    """Walk all test files and extract case IDs from @pytest.mark.conformance markers."""
    suite_dir = Path(__file__).resolve().parent
    case_ids: set[str] = set()
    for path in suite_dir.glob("test_*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                # Match @pytest.mark.conformance("case-id")
                if (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr == "conformance"
                    and decorator.args
                    and isinstance(decorator.args[0], ast.Constant)
                ):
                    case_ids.add(str(decorator.args[0].value))
    return case_ids


def test_catalog_case_ids_are_represented_in_conformance_tests() -> None:
    root = Path(__file__).resolve().parents[1]
    default_catalog_path = root.parent / "conformance" / "oauth-sdk-conformance-catalog.yaml"
    catalog_path = (
        Path(os.environ["CONFORMANCE_CATALOG_PATH"])
        if "CONFORMANCE_CATALOG_PATH" in os.environ
        else default_catalog_path
    )
    catalog_text = catalog_path.read_text(encoding="utf-8")
    cases_text = catalog_text.split("cases:", 1)[1]
    catalog_ids = re.findall(r'^\s+- id: "([^"]+)"\s*$', cases_text, flags=re.MULTILINE)

    marker_ids = _collect_conformance_case_ids()

    missing = [case_id for case_id in catalog_ids if case_id not in marker_ids]
    assert missing == [], f"Catalog cases without @pytest.mark.conformance marker: {missing}"
