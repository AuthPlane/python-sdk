#!/usr/bin/env bash
set -euo pipefail

# Tests for backport-fixes.sh --from ref resolution.
#
# The script has no other test, and the case it regressed on is not one a reader
# would guess: --from accepts a branch OR a tag, and only the branch form has a
# remote-tracking ref. After a release, release.yml deletes the release branch,
# so the tag is the only ref naming those commits — the tag form is the one
# backport-fixes.yml's input description and release.yml's own run summary both
# tell you to use.
#
# Each case builds a throwaway origin + clone in a temp dir, so nothing here
# touches the real repository or the network.
#
# Run: scripts/backport-fixes.test.sh

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/backport-fixes.sh"
failures=0

# Cut the developer's own git config out of the fixtures. Every `git` call below
# — in the suite and inside the script under test — otherwise reads
# ~/.gitconfig, and one maintainer setting is enough to take the whole run down:
# with `commit.gpgsign=true` set globally, make_fixture dies at its first commit
# ("error: cannot run gpg: No such file or directory"), `set -e` aborts before
# any case reports, and the run ends with no summary and exit 128. CI runners
# carry no such config, so it is a local-only failure that reads as a broken
# suite.
#
# GIT_CONFIG_NOSYSTEM, not GIT_CONFIG_SYSTEM=/dev/null. The latter only redirects
# the /etc/gitconfig slot, and Apple Git reads a second system config out of its
# own install tree that the redirect does not cover — so with
# GIT_CONFIG_SYSTEM=/dev/null exported, `git config --get init.defaultBranch`
# still answers `main` from
# /Applications/Xcode.app/.../usr/share/git-core/gitconfig, and the export is a
# silent no-op. GIT_CONFIG_NOSYSTEM=1 is honored by every git, and leaves
# init.defaultBranch unset. The global half is the half that matters here
# (commit.gpgsign lives in ~/.gitconfig) and worked either way, but a guard that
# does nothing on the machine most likely to need it is not a guard.
#
# This does NOT subsume the explicit `-b main` below. With system and global
# config suppressed init.defaultBranch is unset, and `git init` then falls back
# to its built-in default — which is still `master`. Verified; the two guards are
# independent. Under the old spelling that was not reproducible on macOS: Apple's
# un-suppressed system config sets init.defaultBranch=main, so `git init` looked
# like it defaulted to `main` on its own.
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1

# `git log` goes into a variable, never into `grep -q`. Under `set -o pipefail`
# the pipe form hands grep the pipeline's exit status: grep -q stops at its first
# match and closes the read end, git takes SIGPIPE on its next write, and 141 —
# not grep's 0 — is what the caller tests. It bites only once the log outgrows
# the pipe buffer, which is why it does not show up here: verified on a
# 4000-commit history, `git log --oneline | grep -q <first-line match>` exits 141
# under bash with git 2.46.2 and with Apple Git 2.50.1, while the one-line
# `main..HEAD` ranges these cases assert on exit 0, because git's whole output
# fits the buffer and it finishes writing before grep exits. That makes the pipe
# form safe by the size of the log it happens to be fed — not a property a
# fixture should have to keep true. Command substitution has no reader to close.

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n     %s\n' "$1" "$2"; failures=$((failures + 1)); }

# Builds: origin with `main`, a v1.0.0 tag, and one commit after the tag that is
# only reachable from the tag's branch — the shape of a fix landed on a release
# branch during release prep.
make_fixture() {
  local root="$1"
  # -b main explicitly: the default branch name comes from init.defaultBranch,
  # which differs between a developer machine and a CI runner. Without it the
  # fixture builds `master` somewhere and every checkout of `main` fails.
  git init -q -b main "$root/origin"
  git -C "$root/origin" config user.email t@example.com
  git -C "$root/origin" config user.name "Test"
  echo base > "$root/origin/f.txt"
  git -C "$root/origin" add -A
  git -C "$root/origin" commit -qm "base"

  # Clone before the tag exists. A clone made afterwards fetches every tag, which
  # leaves refs/tags/v1.0.0 populated locally and hides whether the script's own
  # fetch materialises it — the exact blind spot that let a broken resolver pass.
  # The real scenario is a maintainer who last fetched before the release.
  git clone -q "$root/origin" "$root/clone"

  git -C "$root/origin" checkout -q -b release/v1.0.0
  echo fix > "$root/origin/f.txt"
  git -C "$root/origin" commit -qam "fix: something landed on the release branch"
  # Annotated, matching release.yml's `git tag -a`. A lightweight tag resolves
  # the same way here, but the fixture should produce what the flow it models
  # produces.
  git -C "$root/origin" tag -a v1.0.0 -m "v1.0.0"
  git -C "$root/origin" checkout -q main
  git -C "$root/clone" config user.email t@example.com
  git -C "$root/clone" config user.name "Test"
}

# --- a branch as --from keeps working -----------------------------------------
t_branch() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out picked
  if out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main 2>&1)"; then
    picked="$(git -C "$root/clone" log --oneline main..HEAD)"
    if [[ "$picked" == *"landed on the release branch"* ]]; then
      pass "a branch as --from cherry-picks its commits"
    else
      fail "a branch as --from cherry-picks its commits" "branch created but the commit is missing"
    fi
  else
    fail "a branch as --from cherry-picks its commits" "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- a tag as --from: the regression ------------------------------------------
# Before the fix this exited 1 with "origin/v1.0.0 not found on remote", because
# origin/<name> resolves only against refs/remotes and a tag has none.
t_tag() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out picked
  if out="$(cd "$root/clone" && "$SCRIPT" --from v1.0.0 --to main 2>&1)"; then
    picked="$(git -C "$root/clone" log --oneline main..HEAD)"
    if [[ "$picked" == *"landed on the release branch"* ]]; then
      pass "a tag as --from cherry-picks its commits"
    else
      fail "a tag as --from cherry-picks its commits" "branch created but the commit is missing"
    fi
  else
    fail "a tag as --from cherry-picks its commits" "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- an unknown ref fails, and leaves nothing behind ---------------------------
# It fails at the resolver, which is what the assertion below pins: `git
# ls-remote --exit-code` exits 2 for a name the remote does not have, both arms
# of fetch_source_ref return non-zero, and the script prints its own message.
# What matters is the contract: non-zero, and no branch created.
t_unknown() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from does-not-exist --to main 2>&1)"; then
    fail "an unknown --from fails" "script exited zero"
  elif [[ -n "$(git -C "$root/clone" branch --list 'backport/*')" ]]; then
    fail "an unknown --from fails" "it created a backport branch anyway"
  elif ! grep -q "as a branch or a tag" <<<"$out"; then
    fail "an unknown --from fails" "reached the fetch, not the resolver: ${out##*$'\n'}"
  else
    pass "an unknown --from fails at the resolver, creating no branch"
  fi
}

# --- --to is branch-only ------------------------------------------------------
# A tag resolves and `git checkout -b` would even work, but backport-fixes.yml
# opens a PR with `--base "$TO"`, which needs a branch on the remote. Rejecting
# it here beats failing after the cherry-picks have run.
t_to_rejects_a_tag() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from main --to v1.0.0 2>&1)"; then
    fail "--to rejects a tag" "script exited zero"
  elif grep -q "must be a branch" <<<"$out"; then
    pass "--to rejects a tag, naming the reason"
  else
    fail "--to rejects a tag" "unexpected message: ${out##*$'\n'}"
  fi
}

# --- a force-pushed source branch still backports ------------------------------
# What the `+` on the refspecs is for. Without it the fetch is a non-fast-forward
# rejection, and the resolver reported that as "not found on origin as a branch
# or a tag" — sending the maintainer after a ref that is present and current.
# Amending a release commit during release prep is routine, and the bare-name
# form this replaced handled it, so losing it would be a regression against main.
t_force_pushed_source() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  # Seed the remote-tracking ref at the pre-amend commit: the state of a
  # maintainer who last fetched before the force-push. Without this the clone
  # has no origin/release/v1.0.0 at all and any fetch is trivially a
  # fast-forward, which is how a missing `+` would go unnoticed.
  git -C "$root/clone" fetch -q origin \
    '+refs/heads/release/v1.0.0:refs/remotes/origin/release/v1.0.0'

  git -C "$root/origin" checkout -q release/v1.0.0
  echo amended > "$root/origin/f.txt"
  git -C "$root/origin" commit -q --amend -am "fix: something landed on the release branch (amended)"
  git -C "$root/origin" checkout -q main

  local out picked
  if out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main 2>&1)"; then
    picked="$(git -C "$root/clone" log --oneline main..HEAD)"
    if [[ "$picked" == *"(amended)"* ]]; then
      pass "a force-pushed source branch backports the rewritten commit"
    else
      fail "a force-pushed source branch backports the rewritten commit" \
        "it backported the pre-amend commit"
    fi
  else
    fail "a force-pushed source branch backports the rewritten commit" \
      "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- a branch wins when a branch and a tag share the name ----------------------
# The arm order in fetch_source_ref decides this and --help now states it, so it
# needs a case: a repo that tags v1.0.0 and later cuts a branch of the same name
# would otherwise silently change which commits get backported.
t_branch_beats_tag() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  # A branch literally named v1.0.0, carrying a commit the tag does not.
  git -C "$root/origin" checkout -q -b v1.0.0 main
  echo from-branch > "$root/origin/f.txt"
  git -C "$root/origin" commit -qam "fix: reached through the branch"
  git -C "$root/origin" checkout -q main

  local out picked
  if out="$(cd "$root/clone" && "$SCRIPT" --from v1.0.0 --to main 2>&1)"; then
    picked="$(git -C "$root/clone" log --oneline main..HEAD)"
    if [[ "$picked" == *"reached through the branch"* ]]; then
      pass "a branch wins over a tag of the same name"
    else
      fail "a branch wins over a tag of the same name" "it resolved the tag instead"
    fi
  else
    fail "a branch wins over a tag of the same name" "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- an unreachable remote is not a missing ref --------------------------------
# `git ls-remote --exit-code` answers 2 for "asked, and the remote has no such
# ref" and 128 for "could not ask" — unreachable, or refused. The 128 arm is the
# one that separates them, and without a case a regression in it is invisible:
# the suite passes while a network failure is reported as a missing ref, sending
# the operator after a ref that is fine.
#
# It asserts the absence of the resolver's message rather than the presence of
# git's, because the wording of `fatal: Could not read from remote repository.`
# is git's to change. What must hold is that the script does not add a claim
# about the ref on top of it.
t_unreachable_remote() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  git -C "$root/clone" remote set-url origin /nonexistent

  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main 2>&1)"; then
    fail "an unreachable remote is not reported as a missing ref" "script exited zero"
  elif grep -q "not found on origin" <<<"$out"; then
    fail "an unreachable remote is not reported as a missing ref" \
         "the network failure was reported as a missing ref"
  elif [[ -n "$(git -C "$root/clone" branch --list 'backport/*')" ]]; then
    fail "an unreachable remote is not reported as a missing ref" "it created a backport branch anyway"
  else
    pass "an unreachable remote is not reported as a missing ref"
  fi
}

# --- a glob as --from is rejected, not resolved --------------------------------
# Neither `git ls-remote` nor a fetch refspec treats these names as literals:
# ls-remote matches its argument as a glob and `*` is legal in a refspec. So
# `--from 'release/*'` used to resolve, fetch wildcard-expanded, and hand
# `git cherry` a name that is not a commit — reported as "Nothing to backport."
# with exit 0.
#
# That is worse than a bare no-op: through backport-fixes.yml it fires
# "::notice::Nothing to backport — all commits on origin/<from> are already
# present on origin/<to>", an actively false statement about a ref that never
# resolved. And it is a regression, not just a gap — before the resolver landed,
# the bare-name fetch died with `fatal: invalid refspec` and exit 128.
#
# Asserted on both arms, because they fail differently: the branch arm expands
# the wildcard against refs/heads, the tag arm against refs/tags.
t_glob_from_rejected() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  local pattern out
  for pattern in 'release/*' 'v1.0.*'; do
    if out="$(cd "$root/clone" && "$SCRIPT" --from "$pattern" --to main 2>&1)"; then
      fail "a glob as --from is rejected ($pattern)" "script exited zero"
    elif grep -q "Nothing to backport" <<<"$out"; then
      fail "a glob as --from is rejected ($pattern)" \
        "the wildcard resolved and the run reported a fact about the refs"
    elif ! grep -q "not a valid ref name" <<<"$out"; then
      fail "a glob as --from is rejected ($pattern)" \
        "rejected, but not by the name check: ${out##*$'\n'}"
    elif [[ -n "$(git -C "$root/clone" branch --list 'backport/*')" ]]; then
      fail "a glob as --from is rejected ($pattern)" "it created a backport branch anyway"
    else
      pass "a glob as --from is rejected before it reaches a refspec ($pattern)"
    fi
  done
}

# --- --branch is validated like --from and --to --------------------------------
# Consistency, not safety: a bad --branch already failed, at `git checkout -b`
# with rc=128 and git's own `fatal: '<x>' is not a valid branch name`, after the
# fetches and the `git cherry` and one line below "Creating branch". Nothing was
# injectable — `-b` consumes the next word, so `--branch --track` is just a
# branch named `--track`. What is pinned here is that all three ref-name inputs
# now fail the same way: exit 2, the script's own message, and before the script
# touches the remote.
#
# That last claim is proved positively, not by asserting the absence of
# "Fetching origin". An absence assertion decays silently — reword that progress
# line and it keeps passing while proving nothing. Instead origin is pointed at a
# path that does not exist for the rejection sub-cases: exiting 2 with the
# script's own message is then only possible if the remote was never contacted,
# because reaching it cannot succeed. The control immediately after is what makes
# that discriminating rather than vacuous — same unreachable origin, a valid
# --branch, which must get past the guard and die at the remote instead.
#
# Not asserted, deliberately: a leading dash. `refs/heads/--track` is a legal
# refname, so `git check-ref-format` accepts it (rc=0) while `git checkout -b`
# refuses it (rc=128, "not a valid branch name") — the one place the two rules
# diverge, over 9 names differentially tested. Closing it would mean hand-rolling
# a rule on top of git's, which is the drift the check-ref-format approach exists
# to avoid, and there is nothing to close: `-b` consumes the next word, so
# `--branch --track` is a branch named `--track`, not an option, and it still
# fails before any cherry-pick.
#
# The second half is the half that keeps the guard honest: a legitimate override
# must still work, or "validated" would just mean "rejected".
t_branch_override_rejects_a_bad_name() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  # Nothing reachable at origin: any success below is proof of ordering, not luck.
  git -C "$root/clone" remote set-url origin /nonexistent-remote

  local name out picked
  for name in 'foo*' 'foo bar' 'foo..bar'; do
    if out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main --branch "$name" 2>&1)"; then
      fail "a bad --branch is rejected ($name)" "script exited zero"
    elif ! grep -q "not a valid ref name" <<<"$out"; then
      fail "a bad --branch is rejected ($name)" \
        "rejected, but not by the name check: ${out##*$'\n'}"
    else
      pass "a bad --branch is rejected up front, before the remote ($name)"
    fi
  done

  # The control for the three above: a name the guard accepts must get further
  # and die at the unreachable remote. Without this, a script that rejected every
  # --branch — or one that never reached the network at all — would satisfy them.
  if out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main --branch backport/my-fix 2>&1)"; then
    fail "a valid --branch passes the guard and reaches the remote" \
      "script exited zero against an unreachable origin"
  elif grep -q "not a valid ref name" <<<"$out"; then
    fail "a valid --branch passes the guard and reaches the remote" \
      "the name check rejected a legitimate override"
  else
    pass "a valid --branch passes the guard and reaches the remote"
  fi

  git -C "$root/clone" remote set-url origin "$root/origin"

  if out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main --branch backport/my-fix 2>&1)"; then
    picked="$(git -C "$root/clone" log --oneline main..HEAD)"
    if [[ "$(git -C "$root/clone" rev-parse --abbrev-ref HEAD)" != "backport/my-fix" ]]; then
      fail "a legitimate --branch is still honored" "the override did not name the branch"
    elif [[ "$picked" != *"landed on the release branch"* ]]; then
      fail "a legitimate --branch is still honored" "branch created but the commit is missing"
    else
      pass "a legitimate --branch override is still honored"
    fi
  else
    fail "a legitimate --branch is still honored" "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- a re-cut tag backports the new commits ------------------------------------
# What the `+` on the tag refspec is for, and the one behavior the resolver's own
# comment claims that nothing pinned. release.yml deletes and re-pushes a tag
# when a release is re-cut; without the force the local tag keeps pointing at the
# superseded commit, and the fetch is rejected with "would clobber existing tag".
t_recut_tag() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  # The state this exists for: a clone that already holds refs/tags/v1.0.0 at the
  # first cut. Without this the local tag is absent and any fetch trivially
  # succeeds, which is how a missing `+` would go unnoticed.
  git -C "$root/clone" fetch -q origin '+refs/tags/v1.0.0:refs/tags/v1.0.0'

  git -C "$root/origin" checkout -q release/v1.0.0
  echo recut > "$root/origin/f.txt"
  git -C "$root/origin" commit -q --amend -am "fix: RE-CUT release"
  git -C "$root/origin" tag -d v1.0.0 >/dev/null
  git -C "$root/origin" tag -a v1.0.0 -m "v1.0.0"
  git -C "$root/origin" checkout -q main

  local out picked
  if out="$(cd "$root/clone" && "$SCRIPT" --from v1.0.0 --to main 2>&1)"; then
    picked="$(git -C "$root/clone" log --oneline main..HEAD)"
    if [[ "$picked" == *"RE-CUT"* ]]; then
      pass "a re-cut tag backports the re-cut commit"
    else
      fail "a re-cut tag backports the re-cut commit" "it backported the superseded commit"
    fi
  else
    fail "a re-cut tag backports the re-cut commit" "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- a force-pushed target branch still backports ------------------------------
# The third refspec. Same failure as t_force_pushed_source but on --to: without
# the `+`, a rewritten origin/main is a non-fast-forward rejection, and the
# resolver reports a present, current branch as "not found on origin".
t_force_pushed_target() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  # Land a commit on main, seed the clone's origin/main at it, then amend it on
  # origin — so the next fetch is a non-fast-forward, which is what the `+` is
  # for. Amending a commit above the base rather than the base itself keeps the
  # two histories sharing a merge-base, so `git cherry` still names exactly the
  # release commit; rewriting the root would leave them unrelated and make every
  # commit a candidate. It touches g.txt, not f.txt, so the cherry-pick applies
  # cleanly and a failure here means the refspec rather than a conflict.
  git -C "$root/origin" checkout -q main
  echo target-side > "$root/origin/g.txt"
  git -C "$root/origin" add -A
  git -C "$root/origin" commit -qm "chore: target-side change"
  git -C "$root/clone" fetch -q origin '+refs/heads/main:refs/remotes/origin/main'
  echo target-side-amended > "$root/origin/g.txt"
  git -C "$root/origin" commit -q --amend -am "chore: target-side change (rewritten)"

  local out base_subject
  if out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main 2>&1)"; then
    # The commit the backport branch was cut from, asserted exactly rather than
    # searched for in a log: this case is about which commit is the base, and
    # HEAD~1 names it. (No pipe, per the note at the top of the file.)
    base_subject="$(git -C "$root/clone" log -1 --format=%s HEAD~1)"
    if [[ "$base_subject" == *"target-side change (rewritten)"* ]]; then
      pass "a force-pushed --to branch is fetched and used as the base"
    else
      fail "a force-pushed --to branch is fetched and used as the base" \
        "the backport branch was cut off the stale origin/main"
    fi
  else
    fail "a force-pushed --to branch is fetched and used as the base" \
      "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- a source with nothing new is a clean no-op --------------------------------
# The one success path the fix touched: `git cherry ... || true` became `if !`,
# so that a cherry which could not run at all stops being reported as "Nothing to
# backport." That rewrite has to leave the legitimate empty result alone, and it
# does — `git cherry` exits 0 with no output — but nothing pinned it, and the
# mistake it invites is cheap to make and expensive to have: treating an empty
# result as a failed comparison turns every no-op backport into an error the
# operator has to go and disprove.
t_nothing_to_backport() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  # A branch that exists and resolves, carrying nothing main does not have — so
  # `git cherry` runs successfully and prints nothing, which is the case the
  # `if !` must not claim as an error.
  git -C "$root/origin" branch nothing-new main

  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from nothing-new --to main 2>&1)"; then
    if ! grep -q "Nothing to backport" <<<"$out"; then
      fail "a source with nothing new is a clean no-op" \
        "exited zero without reporting an empty backport: ${out##*$'\n'}"
    elif [[ -n "$(git -C "$root/clone" branch --list 'backport/*')" ]]; then
      fail "a source with nothing new is a clean no-op" "it created a backport branch anyway"
    else
      pass "a source with nothing new exits 0 with 'Nothing to backport', creating no branch"
    fi
  else
    fail "a source with nothing new is a clean no-op" \
      "an empty result was reported as a failure: ${out##*$'\n'}"
  fi
}

echo "backport-fixes.sh — --from ref resolution"
t_branch
t_tag
t_unknown
t_nothing_to_backport
t_glob_from_rejected
t_branch_override_rejects_a_bad_name
t_to_rejects_a_tag
t_force_pushed_source
t_force_pushed_target
t_recut_tag
t_branch_beats_tag
t_unreachable_remote

if [[ "$failures" -gt 0 ]]; then
  echo "$failures failing"
  exit 1
fi
echo "all passing"
