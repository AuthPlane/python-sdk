# Release setup

One-time operator steps required before the release pipeline can publish to PyPI. All three packages (`authplane-sdk`, `authplane-mcp`, `authplane-fastmcp`) must be configured independently.

## 1. PyPI trusted publishing

For each of the three package names, on [pypi.org](https://pypi.org/):

1. Sign in as an account that owns (or will own) the package name.
2. **Account settings → Publishing → Add a new pending publisher**:
   - **Project name**: `authplane-sdk` (repeat for `authplane-mcp`, `authplane-fastmcp`).
   - **Owner**: `AuthPlane`
   - **Repository name**: `python-sdk`
   - **Workflow name**: `release.yml`
   - **Environment name**: `pypi`
3. Save.

The first successful release to each package name converts the pending publisher into a permanent trusted publisher.

No API tokens are stored in GitHub. Authentication uses short-lived OIDC tokens scoped to the specific workflow + environment.

## 2. GitHub Environment

In the `AuthPlane/python-sdk` repository:

1. **Settings → Environments → New environment → `pypi`**.
2. (Optional) Add **required reviewers** so every release waits for a human approval before uploading to PyPI.
3. (Optional) Restrict the environment to tags matching `v*.*.*` so only the tag-triggered `publish-pypi.yml` workflow can deploy. The release tag is pushed directly onto the `release/v*` / `hotfix/v*` source branch (no merge to the default branch); `publish-pypi.yml` runs on the tag push and publishes to PyPI via OIDC.

## 3. CHANGELOG

The release workflow reads `CHANGELOG.md` for notes. Ensure:

- Every release has a `## [X.Y.Z]` heading on the source branch (`release/v*` or `hotfix/v*`) before running the release workflow.
- The default branch always carries `## [Unreleased]` between releases. The `cut-release` workflow enforces this on `release/v*` cuts (refuses to cut if missing); `hotfix/v*` cuts skip the check because they branch off an older tag.

## 4. Recovery: partial PyPI upload

PyPI does not support atomic multi-package uploads. If the release workflow publishes one or two packages then fails:

1. Download the build artifact from the failed workflow run (named `dist-vX.Y.Z`). It preserves the repo's directory structure: `dist/`, `authplane-mcp/dist/`, `authplane-fastmcp/dist/`.
2. For each package still missing from PyPI, authenticate with `twine` (API token or another trusted-publisher call) and run the matching upload:
   ```bash
   # Root package
   twine upload dist/*
   # MCP adapter
   twine upload authplane-mcp/dist/*
   # FastMCP adapter
   twine upload authplane-fastmcp/dist/*
   ```
3. Manually create the GitHub Release if that step was also skipped:
   ```bash
   gh release create vX.Y.Z --title vX.Y.Z --notes-file <path-to-notes>
   ```
   No `--target` — the tag already points at the correct commit on the (now deleted) source branch.
4. If any commits on the source branch need to reach the default branch, dispatch the **Backport fixes** workflow with `fromBranch=vX.Y.Z` (the tag, not the branch — the branch was deleted after the atomic push).

The git tag is already live, so re-running the workflow is not an option (tag-exists pre-flight will refuse).

## 5. Known pre-existing issue to resolve before the first real release

`authplane-mcp/pyproject.toml` declares `"mcp @ git+https://github.com/modelcontextprotocol/python-sdk.git@main"` as a direct VCS reference (enabled via `[tool.hatch.metadata] allow-direct-references = true`). **PyPI rejects uploads containing direct-URL references**, so the first attempt to publish `authplane-mcp` via this workflow will fail at the upload step. Before cutting the first real release, replace that dependency with a pinned published version of `mcp` (e.g., `"mcp>=X.Y"`). The workflow builds and `twine check`s both will pass; only the actual upload will reject. Dry-run (`dryRun: true`) masks this by skipping the upload.
