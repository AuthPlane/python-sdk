#!/usr/bin/env bash
set -euo pipefail

# Cherry-pick commits from a release/hotfix branch — or from the tag that
# names them once the branch is gone — to a local backport branch off main
# (or another target). Does NOT push, create PRs, or touch remotes beyond
# `git ls-remote` and `git fetch`.
#
# Conflicts use git's native cherry-pick state machine — resolve, then
# `git cherry-pick --continue` (or --skip / --abort). Re-running this
# script is not needed after a conflict; git's sequencer handles it.
#
# Uses `git cherry` for patch-ID-based matching, so commits already
# cherry-picked to the target (under different SHAs) are correctly
# detected and excluded.

usage() {
  cat <<'EOF'
Usage:
  backport-fixes.sh --from <branch|tag> [--to <branch>] [--branch <name>]

Options:
  --from <branch|tag>
                     Source branch OR tag on origin (e.g. release/v0.6.0,
                     hotfix/v0.5.1, v0.6.0). Do not include 'origin/'.
                     Required. After a release, release.yml has deleted
                     release/vX.Y.Z, so the tag is the only ref naming
                     those commits — which is what backport-fixes.yml
                     tells you to pass. A branch wins if a branch and a
                     tag share the name.
  --to <branch>      Target branch on origin (default: main). Branch only:
                     backport-fixes.yml opens a PR with --base, which
                     needs a branch that exists on the remote.
  --branch <name>    Name for the local backport branch (default:
                     `backport/vX.Y.Z` derived from --from when it
                     matches release/vX.Y.Z or hotfix/vX.Y.Z. Anything
                     else — a tag included — is flattened into
                     `backport/<flattened-from>`, so --from v0.6.0
                     gives `backport/v0.6.0`).
  -h, --help         Show this help.

Behavior:
  1. Validates <from> and <to> as ref names (git check-ref-format), then
     asks origin what they name (git ls-remote) and fetches those two
     refs — not the whole remote. The validation is what keeps a glob
     out of the refspecs: `git ls-remote` would match `release/*` as a
     pattern and the fetch would expand it, leaving a name that is not a
     commit.
  2. Lists commits on the resolved <from> ref — origin/<from> for a
     branch, refs/tags/<from> for a tag — that aren't already on
     origin/<to>, and commits that are already there (skipped).
  3. Creates the backport branch off origin/<to>.
  4. Runs `git cherry-pick -x` with the candidates, oldest-first.
  5. On conflict: stops. Resolve, then `git cherry-pick --continue`.

If the backport branch already exists locally, the script fails — delete
it (`git branch -D <name>`) or pass `--branch <other-name>` to override.

No push. No PR. The branch stays local; you decide what to do next.

Examples:
  backport-fixes.sh --from release/v0.6.0
  backport-fixes.sh --from v0.6.0          # after release.yml deleted it
EOF
}

FROM=""
TO="main"
BRANCH_OVERRIDE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from)   FROM="${2-}"; shift 2 ;;
    --to)     TO="${2-}"; shift 2 ;;
    --branch) BRANCH_OVERRIDE="${2-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$FROM" ]]; then
  echo "error: --from is required" >&2
  usage >&2
  exit 2
fi
if [[ -z "$TO" ]]; then
  echo "error: --to cannot be empty" >&2
  exit 2
fi
if [[ "$FROM" == origin/* || "$TO" == origin/* ]]; then
  echo "error: branch names must not include 'origin/'" >&2
  exit 2
fi
if [[ "$FROM" == "$TO" ]]; then
  echo "error: --from and --to must differ" >&2
  exit 2
fi

# Both names reach `git ls-remote` and then a fetch refspec, and neither treats
# them as literals: ls-remote matches its argument as a glob, and `*` is legal
# in a refspec. So `--from 'release/*'` resolves against the remote, fetches
# wildcard-expanded, and leaves FROM_REF naming a pattern rather than a commit —
# which `git cherry` rejects and the run then reports as "Nothing to backport."
# with exit 0. That is a tooling failure presented to the operator as a fact
# about the refs, which is the class of error the resolver below exists to
# remove; through backport-fixes.yml it also fires the "all commits on
# origin/<from> are already present on origin/<to>" notice about a ref that never
# resolved. Before the resolver landed the same input died at the fetch with
# `fatal: invalid refspec` and exit 128, so leaving it would be a regression.
#
# `git check-ref-format` is git's own refname(7) rule set, so this cannot drift
# from what git accepts: it rejects `*`, whitespace, `..`, control characters and
# the rest. Checking here rather than after resolution keeps the wildcard out of
# ls-remote, the fetch and `git checkout -b` alike.
if ! git check-ref-format "refs/heads/$FROM" 2>/dev/null; then
  echo "error: --from is not a valid ref name: $FROM" >&2
  exit 2
fi
if ! git check-ref-format "refs/heads/$TO" 2>/dev/null; then
  echo "error: --to is not a valid ref name: $TO" >&2
  exit 2
fi
# --branch is the third name that becomes a ref, and it is checked here for
# consistency rather than for safety. A bad value already fails: `git checkout -b`
# exits 128 with `fatal: '<x>' is not a valid branch name`, before any
# cherry-pick, and there is nothing to inject because `-b` consumes the next word
# whatever it looks like (`--branch --track` fails as the branch name `--track`,
# not as an option). What the check buys is that all three ref-name inputs fail
# the same way — up front, exit 2, with the script's own message — instead of two
# of three doing that while the last dies on a raw git fatal after the fetches
# and the `git cherry`, one line below "Creating branch". The derived names need
# no check: they come from the already-validated $FROM through a substitution
# that only removes characters.
#
# One divergence, left alone on purpose: `refs/heads/--track` is a legal refname,
# so check-ref-format accepts it while `git checkout -b` refuses it. Matching that
# would mean hand-rolling a rule on top of git's, which is exactly the drift using
# git's own rule set avoids — and it costs nothing, since such a name still fails
# at the checkout, before any cherry-pick.
if [[ -n "$BRANCH_OVERRIDE" ]] && ! git check-ref-format "refs/heads/$BRANCH_OVERRIDE" 2>/dev/null; then
  echo "error: --branch is not a valid ref name: $BRANCH_OVERRIDE" >&2
  exit 2
fi

# Must be in a git repo
if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "error: not inside a git repository" >&2
  exit 1
fi

# Detect in-progress cherry-pick first — gives a more actionable error
# than the generic dirty-tree check, which also trips during a conflict.
if [[ -f "$(git rev-parse --git-dir)/CHERRY_PICK_HEAD" ]]; then
  echo "error: a cherry-pick is already in progress. Finish or abort it first:" >&2
  echo "       git cherry-pick --continue | --skip | --abort" >&2
  exit 1
fi

# Require clean working tree — cherry-picks onto a dirty tree are unsafe.
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "error: working tree has uncommitted changes. Commit or stash first." >&2
  exit 1
fi

echo "Fetching origin..."

# Fetch and resolve in one step, because the two have to agree about where a ref
# lands. A bare-name refspec — `git fetch origin v1.0.0` — writes FETCH_HEAD and
# nothing else: no refs/tags entry, no remote-tracking ref. Fetching that way and
# then looking under refs/tags only works when the tag happens to be there
# already, which is true of a clone made after the release and false for the
# maintainer this path exists for: someone whose last fetch predates the tag.
#
# An explicit destination refspec materialises it. Both refspecs below carry a
# leading `+`: the bare-name form they replaced still got its remote-tracking
# update through `remote.origin.fetch`, whose refspec is forced. Writing the
# destination out without the `+` silently drops that force, and a source branch
# that was force-pushed — routine during release prep, e.g. an amended release
# commit — stops fast-forwarding and fails a backport that used to work.
#
# Ask the remote what a name is before fetching it, instead of attempting a
# fetch and reading its failure as absence. `git ls-remote --exit-code` answers
# 0 (the ref is there), 2 (the remote answered and has no such ref) or 128 (the
# remote was unreachable, or refused us). Only 2 means "not found"; reporting
# 128 as a missing ref sends the operator after the ref when the ref is fine.
#
# The fetches below run without -q on purpose: -q suppresses the per-ref status
# table, which is where `! [rejected]` is written, so a fetch that fails after
# ls-remote said the ref was there would exit with no explanation at all.
remote_ref_exists() {
  local rc=0
  git ls-remote --exit-code origin "$1" >/dev/null || rc=$?
  case "$rc" in
    0) return 0 ;;
    2) return 1 ;;
    # git has already described the failure on stderr; adding a guess about the
    # ref on top of it would only mislead.
    *) exit 1 ;;
  esac
}

# These assign to FROM_REF / TO_REF rather than echoing their result. Called as
# `$(...)`, the body would run in a subshell, where the `exit 1` above exits
# only that subshell and the caller carries on with an empty ref.
FROM_REF=""
TO_REF=""

# --from accepts a branch or a tag. After a release, release.yml has deleted
# release/vX.Y.Z, so the tag is the only ref naming those commits.
fetch_source_ref() {
  local name="$1"
  if remote_ref_exists "refs/heads/$name"; then
    git fetch origin "+refs/heads/$name:refs/remotes/origin/$name" || exit 1
    FROM_REF="origin/$name"
  elif remote_ref_exists "refs/tags/$name"; then
    # A re-cut tag (deleted on origin and re-pushed at a new commit) lands here.
    # `+` overwrites the stale local tag, which otherwise keeps pointing at the
    # superseded release and would backport the wrong commits.
    git fetch origin "+refs/tags/$name:refs/tags/$name" || exit 1
    FROM_REF="refs/tags/$name"
  else
    return 1
  fi
}

# --to is branch-only, deliberately. A tag would resolve and `git checkout -b`
# would even work, but backport-fixes.yml opens a PR with `--base "$TO"`, which
# needs a branch that exists on the remote.
fetch_target_ref() {
  local name="$1"
  if remote_ref_exists "refs/heads/$name"; then
    git fetch origin "+refs/heads/$name:refs/remotes/origin/$name" || exit 1
    TO_REF="origin/$name"
  else
    return 1
  fi
}

if ! fetch_source_ref "$FROM"; then
  echo "error: $FROM not found on origin as a branch or a tag" >&2
  exit 1
fi
if ! fetch_target_ref "$TO"; then
  echo "error: $TO not found on origin as a branch (--to must be a branch)" >&2
  exit 1
fi

# `git cherry -v <upstream> <head>` prints one line per commit:
#   + <sha> <subject>   -> not on upstream (candidate for backport)
#   - <sha> <subject>   -> already on upstream via patch-ID match
#
# Checked, not `|| true`. `git cherry` exits 0 whether or not there are
# candidates, so a non-zero here means it could not do the comparison at all —
# and swallowing that re-merges "genuinely nothing to backport" with "something
# went wrong", which is the exact distinction the resolver above exists to keep.
# `if !` rather than a bare call so the message names both refs; a bare call
# under `set -e` would exit with git's line alone.
if ! cherry_out="$(git cherry -v "$TO_REF" "$FROM_REF")"; then
  echo "error: could not compare $FROM_REF against $TO_REF" >&2
  exit 1
fi

candidates_pretty="$(echo "$cherry_out" | awk '$1 == "+" { sub(/^\+ /, ""); print }')"
already_pretty="$(echo   "$cherry_out" | awk '$1 == "-" { sub(/^- /, "");  print }')"
shas="$(echo "$cherry_out" | awk '$1 == "+" { print $2 }')"

n_candidates=0
[[ -n "$candidates_pretty" ]] && n_candidates=$(echo "$candidates_pretty" | wc -l | tr -d ' ')
n_already=0
[[ -n "$already_pretty" ]] && n_already=$(echo "$already_pretty" | wc -l | tr -d ' ')

echo
echo "=== Commits on $FROM_REF not yet on $TO_REF ($n_candidates) ==="
if [[ "$n_candidates" -gt 0 ]]; then
  echo "$candidates_pretty"
else
  echo "(none)"
fi

if [[ "$n_already" -gt 0 ]]; then
  echo
  echo "=== Already on $TO_REF, excluded ($n_already) ==="
  echo "$already_pretty"
fi

if [[ "$n_candidates" -eq 0 ]]; then
  echo
  echo "Nothing to backport."
  exit 0
fi

if [[ -n "$BRANCH_OVERRIDE" ]]; then
  branch="$BRANCH_OVERRIDE"
elif [[ "$FROM" =~ ^(release|hotfix)/v([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
  branch="backport/v${BASH_REMATCH[2]}"
else
  flat="$(echo "$FROM" | sed -E 's|/|-|g; s/[^a-zA-Z0-9._-]+/-/g')"
  branch="backport/${flat}"
fi

if git show-ref --verify --quiet "refs/heads/$branch"; then
  echo "error: local branch '$branch' already exists." >&2
  echo "       Delete it (git branch -D $branch) or pass --branch <other-name>." >&2
  exit 1
fi

echo
echo "Creating branch $branch off $TO_REF..."
git checkout -b "$branch" "$TO_REF"

echo
echo "Cherry-picking $n_candidates commit(s) with -x, oldest first..."
echo "If git stops on a conflict:"
echo "  - Resolve, 'git add <files>', then 'git cherry-pick --continue'."
echo "  - To drop the conflicting commit: 'git cherry-pick --skip'."
echo "  - To bail out entirely:           'git cherry-pick --abort'."
echo

# shellcheck disable=SC2086 # intentional word-split: $shas is a hex-only list
exec git cherry-pick -x $shas
