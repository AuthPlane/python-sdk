# Contributing to the Authplane Python SDK

Thanks for your interest in contributing. This repository is a monorepo publishing three packages to PyPI:

| PyPI dist | Import | Directory |
|---|---|---|
| `authplane-sdk` | `authplane` | `authplane/` |
| `authplane-mcp` | `authplane_mcp` | `authplane-mcp/` |
| `authplane-fastmcp` | `authplane_fastmcp` | `authplane-fastmcp/` |

Adapters depend on `authplane-sdk`. A single tagged release publishes all three.

## Reporting Issues

- **Bugs:** open a [bug report](https://github.com/AuthPlane/python-sdk/issues/new?template=bug-report.md). Include package name, version, Python version, and a minimal reproduction.
- **MCP client compatibility:** use the [MCP Compatibility Report](https://github.com/AuthPlane/python-sdk/issues/new?template=mcp-compatibility.md) template.
- **Feature requests:** open a [feature request](https://github.com/AuthPlane/python-sdk/issues/new?template=feature-request.md). Describe the problem, then the proposed solution.
- **Security vulnerabilities:** do **not** open a public issue. See [SECURITY.md](SECURITY.md).

## Development Setup

### Prerequisites

- Python 3.11, 3.12, or 3.13
- `git`
- A virtual environment tool (`python -m venv`, `uv`, or similar)

### Install

Clone the repo and install the root SDK with dev extras:

```bash
git clone https://github.com/AuthPlane/python-sdk.git
cd python-sdk
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

If you plan to work on an adapter, also install it editable:

```bash
pip install -e "authplane-mcp[dev]"
pip install -e "authplane-fastmcp[dev]"
```

Adapters depend on `authplane-sdk` as a PyPI dep, so the root install above must happen first for editable cross-linking.

## Local Verification

Run the same checks CI runs before opening a PR.

**Lint and format:**

```bash
ruff check .
ruff format --check .
```

Use `ruff format .` to auto-fix formatting. Use `ruff check --fix .` for safe autofixes.

**Type-check (SDK root only):**

```bash
pyright
```

The adapters don't run `pyright` in CI today; treat any type errors they surface as advisory.

**Tests:**

```bash
pytest tests                                          # root SDK
(cd authplane-mcp && pytest tests)                    # MCP adapter
(cd authplane-fastmcp && pytest tests)                # FastMCP adapter
```

**Conformance tests (shared catalog required):**

The conformance suite in `conformance-tests/` validates the SDK against the shared OAuth SDK Conformance Catalog, which lives in [`AuthPlane/conformance`](https://github.com/AuthPlane/conformance). Clone that repo as a **sibling** of your `python-sdk/` clone:

```bash
# From the directory that contains your python-sdk/ clone
git clone https://github.com/AuthPlane/conformance.git
```

Expected layout:

```
parent-dir/
├── python-sdk/
└── conformance/
    └── oauth-sdk-conformance-catalog.yaml
```

Then run:

```bash
pytest conformance-tests/
```

`conformance-tests/conftest.py` resolves the catalog at `../conformance/oauth-sdk-conformance-catalog.yaml` by default. Set `AUTHPLANE_CONFORMANCE_CATALOG=/absolute/path/to/oauth-sdk-conformance-catalog.yaml` to override (useful if your checkout layout differs). Without the catalog, `conformance-tests/` fails with a clear error — the rest of the test suite still runs.

**Coverage (matches CI):**

```bash
coverage run -m pytest tests && coverage report
```

Coverage fails below 80% — see `pyproject.toml` → `[tool.coverage.report] fail_under`.

**Package build smoke test:**

```bash
python -m build
twine check dist/*
```

## Pull Request Guidelines

- Branch off `main`. Release branches (`release/v*`, `hotfix/v*`) are managed by the release flow — see [RELEASE_POLICY.md](RELEASE_POLICY.md).
- PR titles follow [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `ci:`, `deps:`, `refactor:`, `test:`, `chore:`.
- Link any related GitHub issue in the PR description (e.g., `Fixes #123`).
- Fill out the PR template (summary, testing, checklist).
- Keep PRs focused. Large, multi-theme PRs are hard to review and easy to stall.

## Changelog

User-facing changes go in [`CHANGELOG.md`](CHANGELOG.md) under the `[Unreleased]` heading. Follow the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format. Release tooling moves entries from `[Unreleased]` to the release version on tag.

## GitHub Actions — SHA-pinning

All workflow actions must be SHA-pinned with a version comment:

```yaml
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

When editing or adding a workflow, run [`pinact`](https://github.com/suzuki-shunsuke/pinact) to pin any new `uses:` lines before committing:

```bash
pinact run
```

Dependabot opens weekly PRs to bump the SHAs (see [`.github/dependabot.yml`](.github/dependabot.yml)).

## Release Process

Releases follow a single-branch flow driven by the release workflow: `release/v*` (or `hotfix/v*`) branches are cut off the default branch, tagged in place, then deleted after the tag is pushed. The detailed procedure lives in [RELEASE_POLICY.md](RELEASE_POLICY.md) and [RELEASE_SETUP.md](RELEASE_SETUP.md). As a contributor you don't need to trigger releases — maintainers handle them.

## Running the Demo

The end-to-end demo exercises FastMCP and MCP adapters against a local Authplane authorization server.

Prerequisites:

1. OAuth server running locally on `:9000`/`:9001` with client credentials, token exchange, and DPoP enabled.
2. Demo client registration with required grant types and scopes.
3. Adapter demo server (`authplane-fastmcp/demo/run.sh` or `authplane-mcp/demo/run.sh`).
4. Demo client execution (Python or TypeScript matrix client).

Entry points:

- `authplane-fastmcp/demo/run.sh`
- `authplane-mcp/demo/run.sh`

### Manual E2E smoke

Helper scripts in `scripts/` boot a local authserver and run a smoke check:

```bash
# Start local authserver and register client/scopes/user.
bash scripts/manual-e2e-setup.sh

# Smoke against the MCP adapter (default).
bash scripts/manual-e2e-smoke.sh --skip-setup

# Smoke against the FastMCP adapter.
bash scripts/manual-e2e-smoke.sh --adapter fastmcp --skip-setup
```

Optional overrides:

- `AUTHSERVER_DIR=/path/to/authserver`
- `ISSUER_URL=http://localhost:9000`
- `RESOURCE_URL=http://localhost:8080/mcp`

### Common demo failures

- `client_credentials grant is not enabled` — OAuth server is missing `AUTHPLANE_CLIENT_CREDENTIALS_ENABLED=true`.
- `client is not authorized for this grant type` — client registration is missing `urn:ietf:params:oauth:grant-type:token-exchange`.
- `requested scope is invalid or not allowed` — requested scopes are not registered or assigned to the demo client.
- `invalid API key` — admin API requests are using a different key than the server startup key.

## Code of Conduct

Be kind. Disagree on substance, not people. Projects that aren't kind don't last.
