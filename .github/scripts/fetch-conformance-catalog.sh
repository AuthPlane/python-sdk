#!/usr/bin/env bash
#
# Fetch the conformance catalog at the revision this repo pins.
#
# Generic: nothing here is specific to one workflow or one caller's layout.
# Every workflow in this repo that needs the pinned catalog runs this one
# script, so a guard tightened here is tightened for all of them.
#
# The catalog lives in github.com/AuthPlane/conformance — a public repo, updated
# independently of this one — so cloning its default branch would let a catalog
# change turn an unrelated PR red here. The ref is pinned instead, single-sourced
# from the tracked .conformance-catalog-ref at the repo root: bump it when
# adopting new catalog cases, together with the coverage for them, so a catalog
# change can never break CI on its own.
#
# This script exists because the read/guard/fetch sequence is needed by more than
# one workflow (ci.yml, release.yml and conformance-catalog-drift.yml). Kept
# inline in each, the guard could be tightened in one and not the others; the pin
# would be single-sourced but the logic reading it would not.
#
# Clones into $RUNNER_TEMP — outside $GITHUB_WORKSPACE — so the catalog stays out
# of the working tree: it must never be picked up by this repo's own build, test
# or coverage tooling, and `git add -A` in the release commit must never stage it
# as an embedded gitlink.
#
# Plain git over HTTPS is enough: the repo is public and read-only here, so there
# is no token to plumb and no third-party action surface to SHA-pin.
#
# Requires: GITHUB_WORKSPACE, RUNNER_TEMP.
#
# Optional: CONFORMANCE_CATALOG_DEST overrides the clone directory. A caller that
# needs the pinned catalog and the catalog tip side by side in the same job
# cannot let both land on the default path. Every other caller leaves it unset
# and gets $RUNNER_TEMP/conformance.

set -euo pipefail

: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE must be set}"
: "${RUNNER_TEMP:?RUNNER_TEMP must be set}"

REF_FILE="$GITHUB_WORKSPACE/.conformance-catalog-ref"
DEST="${CONFORMANCE_CATALOG_DEST:-$RUNNER_TEMP/conformance}"
CATALOG_REPO="https://github.com/AuthPlane/conformance.git"
CATALOG_FILE="oauth-sdk-conformance-catalog.yaml"

if [[ ! -f "$REF_FILE" ]]; then
  echo "::error::$REF_FILE is missing; the conformance catalog revision is unpinned"
  exit 1
fi

CONFORMANCE_CATALOG_REF="$(tr -d '[:space:]' < "$REF_FILE")"

# Guard against un-pinning BEFORE the fetch: the ref must be a full commit SHA,
# not a branch or tag name, either of which would silently track a moving target.
if ! grep -Eq '^[0-9a-f]{40}$' <<< "$CONFORMANCE_CATALOG_REF"; then
  echo "::error::.conformance-catalog-ref must be a 40-hex commit SHA, got '$CONFORMANCE_CATALOG_REF'"
  exit 1
fi

git init -q "$DEST"
if ! git -C "$DEST" fetch --depth=1 "$CATALOG_REPO" "$CONFORMANCE_CATALOG_REF"; then
  echo "::error::Pinned conformance catalog ref $CONFORMANCE_CATALOG_REF is unreachable"
  exit 1
fi
git -C "$DEST" checkout -q FETCH_HEAD

# The alignment assertion hard-fails when CONFORMANCE_CATALOG_PATH points at a
# missing file, but it reports that as a harness problem rather than drift. Fail
# here instead, where the cause is unambiguous: the fetch succeeded and the
# catalog still is not where every caller expects it.
if [[ ! -f "$DEST/$CATALOG_FILE" ]]; then
  echo "::error::$CATALOG_FILE is not in the catalog at $CONFORMANCE_CATALOG_REF; the fetch succeeded but produced no catalog in $DEST"
  exit 1
fi

echo "Conformance catalog checked out at $CONFORMANCE_CATALOG_REF in $DEST"
