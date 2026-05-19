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
    "rfc9449-dpop-proof-jwk-must-not-include-private-key-material",
    level="partial",
    gaps=["expected.error_hint"],
    note="Python rejects the proof but does not expose a stable diagnostic.",
)
async def test_...(...):
    ...
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `level` | `"full"` | `"full"` or `"partial"` — how closely the test matches the catalog spec |
| `gaps` | `[]` | List of expected catalog fields not covered by this test |
| `note` | `""` | Free-text explanation (appears in both JSON and Markdown reports) |

### Not-yet-implemented tests

Tests for features that don't exist yet should still be present with the marker and a `pytest.xfail(...)` body that documents what is missing:

```python
@pytest.mark.conformance(
    "rfc9449-dpop-inbound-nonce-must-be-validated-when-required",
    note="Not implemented: the SDK has no nonce generation, DPoP-Nonce challenge emission, or challenge-retry lifecycle for resource servers.",
)
async def test_rfc9449_dpop_inbound_nonce_must_be_validated_when_required(...):
    pytest.xfail("Not implemented: ...")
```

These tests show up as `skipped` (with their `note` carried through) in both `conformance-report.json` and `conformance-report.md` — pytest classifies `xfail` outcomes as skips. Keeping the suite green for known gaps means CI never has to be ignored to merge; the gap is still visible in the report's per-case status and coverage notes.

## Running

The suite needs the shared catalog YAML on disk. By default it looks for
`../conformance/oauth-sdk-conformance-catalog.yaml` (i.e. `python-sdk` and
[`conformance`](https://github.com/AuthPlane/conformance) checked out as
siblings). If your layout differs — e.g. nested inside another monorepo —
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
| `test_catalog_alignment.py` | Meta-test: ensures every catalog case has a `@pytest.mark.conformance` marker |
| `conftest.py` | Harness: marker extraction, result collection, report generation |

## Catalog Alignment

`test_catalog_alignment.py` uses AST parsing to verify that every case ID in the shared catalog has a corresponding `@pytest.mark.conformance("case-id")` marker somewhere in the suite. If a new case is added to the catalog without a matching test, this check fails.
