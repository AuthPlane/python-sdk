# Conformance Test Suite

This directory contains the Python SDK conformance tests, mapped to the shared [OAuth SDK Conformance Catalog](../../conformance/oauth-sdk-conformance-catalog.yaml).

## How It Works

### Marker-based mapping

Each test is mapped to a catalog case ID via `@pytest.mark.conformance`:

```python
@pytest.mark.conformance("rfc9068-valid-at-jwt-must-verify")
async def test_rfc9068_valid_at_jwt_must_verify(verifier, token_factory):
    claims = await verifier.verify(token_factory())
    assert claims.sub == "user123"
```

There is no external mapping file — the case ID lives on the test itself.

### Coverage metadata

Tests can carry optional coverage metadata to flag partial coverage or known gaps against the catalog spec:

```python
@pytest.mark.conformance(
    "<catalog-case-id>",
    level="partial",
    gaps=["expected.error_hint"],
    note="<which part of the case the test does not reach>",
)
async def test_...(...):
    ...
```

The case id is a placeholder on purpose: naming a real one here would claim
coverage metadata that the marker on the actual test may not carry.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `level` | `"full"` | `"full"` or `"partial"` — how closely the test matches the catalog spec. Always reaches `conformance-report.md`. |
| `gaps` | `[]` | Catalog *field paths* the test does not reach (`use_case`, `expected.error_hint`, …). Reaches `conformance-report.md` only alongside a `note`; always reaches `conformance-report.json`. |
| `note` | `""` | Free-text prose. Gates the Coverage Notes section — see below. |

Keep them in that order — `gaps` names the fields, `note` carries the prose —
and **always write a `note` alongside `gaps`, because `note` is the gate**. In
`conftest.py`'s `_build_markdown_report`, a single filter (`:216`) selects the
cases with a truthy `note`, and it decides both whether the Coverage Notes
section is emitted at all (`:217`) and which cases it lists (`:219`) — and the
`Gaps:` line (`:224-225`) is emitted *inside* that section. So a `gaps`-only
marker states no reason anywhere in `conformance-report.md` and its `gaps`
survive in `conformance-report.json` alone; set a `note` and both render.

`level` is not gated on `note`: it reaches the markdown either way, via the
Cases table's Coverage column (`:193-197`).

Also keep `|` out of the `note` — it is interpolated into a markdown table cell
unescaped and will break the row.

### Partial coverage vs. not implemented

A test that exercises part of a case but not all of it is a `partial`: it still
runs and still asserts. Prefer that over an `xfail` wherever one is honest — an
`xfail` asserts nothing, so it cannot notice the day the gap closes, and it
reports as a skip while the report carries the case as not-run.

A case with nothing behind it at all should carry the marker with a
`pytest.xfail(...)` body documenting what is missing:

```python
@pytest.mark.conformance(
    "<catalog-case-id>",
    note="Not implemented: <what the SDK does not have>.",
)
async def test_<catalog_case_id>(...):
    pytest.xfail("Not implemented: ...")
```

The id is a placeholder deliberately: **the suite currently has no `xfail`s**,
so there is no live case to point at, and `test_catalog_alignment.py` requires
every catalog id to carry a marker — so any real id named here would be one
that does have a test behind it. (This section previously used
`rfc9449-dpop-inbound-nonce-must-be-validated-when-required` as its worked
example; that case now runs as a `partial`.)

`xfail` tests show up as `skipped` — with their `note` carried through — in both
`conformance-report.json` and `conformance-report.md`, because pytest
classifies `xfail` outcomes as skips. Keeping the suite green for known gaps
means CI never has to be ignored to merge; the gap stays visible in the
report's per-case status and coverage notes.

## Running

The suite needs the shared catalog YAML on disk. By default it looks for
`../conformance/oauth-sdk-conformance-catalog.yaml` (i.e. `python-sdk` and
[`conformance`](https://github.com/AuthPlane/conformance) checked out as
siblings). To match CI exactly, check out the catalog revision pinned in
`.conformance-catalog-ref` at the repo root rather than the latest default
branch:

```bash
# From the python-sdk/ clone, with conformance/ checked out as a sibling
git -C ../conformance checkout "$(cat .conformance-catalog-ref)"
```

If your layout differs — e.g. nested inside another monorepo —
point the suite at the catalog explicitly:

```bash
export AUTHPLANE_CONFORMANCE_CATALOG=/abs/path/to/oauth-sdk-conformance-catalog.yaml
```

The suite refuses to start with a clear error if the catalog cannot be
found.

```bash
# Run the conformance suite
pytest conformance-tests/

# Run alongside the main test suite
pytest tests/ conformance-tests/
```

## Reports

After each run, two reports are generated in the project root:

- **`conformance-report.json`** — Machine-readable results with case IDs, status, coverage metadata, and failure details.
- **`conformance-report.md`** — Human-readable Markdown with summary, cases table (including notes column), failures, and coverage notes.

## Test Files

| File | Scope |
|------|-------|
| `test_jwt_and_dpop_conformance.py` | RFC 9068, RFC 8725, RFC 9449, RFC 9728 |
| `test_oauth_protocol_conformance.py` | RFC 6749, RFC 7009, RFC 7662, RFC 8693, RFC 8707 |
| `test_rfc8414_conformance.py` | RFC 8414 |
| `test_catalog_alignment.py` | Meta-test: catalog and `@pytest.mark.conformance` markers agree in both directions |
| `conftest.py` | Harness: marker extraction, result collection, report generation |

## Catalog Alignment

`test_catalog_alignment.py` uses AST parsing to compare the case IDs in the
shared catalog against the `@pytest.mark.conformance("case-id")` markers in the
suite, and asserts that they agree in **both** directions:

| Test | Fails when |
|------|------------|
| `test_catalog_case_ids_are_represented_in_conformance_tests` | A catalog case has no marker — the SDK does not cover it, and the report carries it as `not_run`. |
| `test_conformance_markers_name_only_catalog_case_ids` | A marker names a case ID the catalog does not carry — a typo, a renamed case, or a case dropped from the catalog. |

Neither direction implies the other. The report in `conftest.py` is built by
iterating the *catalog's* case IDs, so a marker naming an unknown ID is dropped
from it silently: without the second check the run stays green while the catalog
case that marker was meant to cover has no coverage at all.

Together they are what makes a `.conformance-catalog-ref` bump safe in both
directions — bumping the pin without adding markers goes red on the first check,
and adding markers without bumping the pin goes red on the second.
