#!/usr/bin/env bash
set -euo pipefail

# Cherry-pick commits from a release/hotfix branch to a local backport
# branch off main (or another target). Does NOT push, create PRs, or
# touch remotes beyond `git fetch`.
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
  backport-fixes.sh --from <branch> [--to <branch>] [--branch <name>]

Options:
  --from <branch>    Source branch on origin (e.g. release/v0.6.0,
                     hotfix/v0.5.1). Do not include 'origin/'. Required.
  --to <branch>      Target branch on origin (default: main).
  --branch <name>    Name for the local backport branch (default:
                     `backport/vX.Y.Z` derived from --from when it
                     matches release/vX.Y.Z or hotfix/vX.Y.Z; otherwise
                     `backport/<flattened-from>`).
  -h, --help         Show this help.

Behavior:
  1. Fetches origin.
  2. Lists commits on origin/<from> that aren't already on origin/<to>,
     and commits that are already there (skipped).
  3. Creates the backport branch off origin/<to>.
  4. Runs `git cherry-pick -x` with the candidates, oldest-first.
  5. On conflict: stops. Resolve, then `git cherry-pick --continue`.

If the backport branch already exists locally, the script fails — delete
it (`git branch -D <name>`) or pass `--branch <other-name>` to override.

No push. No PR. The branch stays local; you decide what to do next.

Example:
  backport-fixes.sh --from release/v0.6.0
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
git fetch origin "$FROM" "$TO" --no-tags

if ! git rev-parse --verify "origin/$FROM" >/dev/null 2>&1; then
  echo "error: origin/$FROM not found on remote" >&2
  exit 1
fi
if ! git rev-parse --verify "origin/$TO" >/dev/null 2>&1; then
  echo "error: origin/$TO not found on remote" >&2
  exit 1
fi

# `git cherry -v <upstream> <head>` prints one line per commit:
#   + <sha> <subject>   -> not on upstream (candidate for backport)
#   - <sha> <subject>   -> already on upstream via patch-ID match
cherry_out="$(git cherry -v "origin/$TO" "origin/$FROM" || true)"

candidates_pretty="$(echo "$cherry_out" | awk '$1 == "+" { sub(/^\+ /, ""); print }')"
already_pretty="$(echo   "$cherry_out" | awk '$1 == "-" { sub(/^- /, "");  print }')"
shas="$(echo "$cherry_out" | awk '$1 == "+" { print $2 }')"

n_candidates=0
[[ -n "$candidates_pretty" ]] && n_candidates=$(echo "$candidates_pretty" | wc -l | tr -d ' ')
n_already=0
[[ -n "$already_pretty" ]] && n_already=$(echo "$already_pretty" | wc -l | tr -d ' ')

echo
echo "=== Commits on origin/$FROM not yet on origin/$TO ($n_candidates) ==="
if [[ "$n_candidates" -gt 0 ]]; then
  echo "$candidates_pretty"
else
  echo "(none)"
fi

if [[ "$n_already" -gt 0 ]]; then
  echo
  echo "=== Already on origin/$TO, excluded ($n_already) ==="
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
echo "Creating branch $branch off origin/$TO..."
git checkout -b "$branch" "origin/$TO"

echo
echo "Cherry-picking $n_candidates commit(s) with -x, oldest first..."
echo "If git stops on a conflict:"
echo "  - Resolve, 'git add <files>', then 'git cherry-pick --continue'."
echo "  - To drop the conflicting commit: 'git cherry-pick --skip'."
echo "  - To bail out entirely:           'git cherry-pick --abort'."
echo

# shellcheck disable=SC2086 # intentional word-split: $shas is a hex-only list
exec git cherry-pick -x $shas
