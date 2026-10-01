#!/usr/bin/env bash
#
# Detect semantic drift in the conformance catalog: a case whose BODY changed
# under an unchanged id.
#
# Everything else in the alignment machinery compares case IDS. The pinned ref
# protects against new cases arriving unannounced, and the drift job's id-set
# comparison against the catalog tip reports cases added or removed. Neither
# looks at the body of a case, so a case that is re-tightened in place — same
# id, stricter requirement — is invisible end to end: the SDK bumps its pin and
# starts declaring conformance to a requirement nothing verified it against.
# That has already happened once, to the metadata jwks_uri rotation case.
#
# This script closes that gap. It compares the body of every case the SDK
# actually registers between two checkouts of the catalog — normally the pinned
# ref and the tip — and fails naming any case whose body changed.
#
# Scoped to the ids the SDK registers on purpose. Diffing the whole catalog, or
# asserting catalog_version, fires on every catalog edit including cases this
# SDK does not cover; the noise is what gets a guard ignored.
#
# Inputs (environment):
#   PINNED_CATALOG  path to the catalog YAML at the ref this repo pins
#   TIP_CATALOG     path to the catalog YAML to compare against
#   REGISTERED_IDS  path to a file holding one case id per line — the ids this
#                   SDK registers. Produced per-repo; for this repo, by
#                   conformance-registered-case-ids.sh.
#   DRIFT_SUMMARY   optional path to append a Markdown summary to
#   COVERAGE_DIR    optional directory to name in that summary as the place the
#                   conformance coverage lives, so the one human-facing pointer
#                   in this script is not the thing that has to be edited when
#                   it is dropped into a tree laid out differently. Defaults to
#                   this repo's core/conformancetests/.
#
# Exit status:
#   0  no body drift in any registered case
#   1  body drift found, OR this check could not do its job
#
# The second half of that exit code matters as much as the first. A guard that
# under-checks while reporting green is the defect class this script exists to
# close, so every input it cannot read, every catalog shape it cannot parse and
# every empty intermediate result is a hard failure rather than a quiet pass.

set -euo pipefail

: "${PINNED_CATALOG:?PINNED_CATALOG must be set}"
: "${TIP_CATALOG:?TIP_CATALOG must be set}"
: "${REGISTERED_IDS:?REGISTERED_IDS must be set}"

DRIFT_SUMMARY="${DRIFT_SUMMARY:-}"
COVERAGE_DIR="${COVERAGE_DIR:-core/conformancetests/}"

fail() {
  echo "::error::$1" >&2
  exit 1
}

for input in "$PINNED_CATALOG" "$TIP_CATALOG" "$REGISTERED_IDS"; do
  if [[ ! -f "$input" || ! -r "$input" ]]; then
    fail "case-body drift check: '$input' is not a readable regular file. The check cannot run and is not reporting a clean result."
  fi
  if [[ ! -s "$input" ]]; then
    fail "case-body drift check: '$input' is empty. The check cannot run and is not reporting a clean result."
  fi
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# Case body extraction
# ---------------------------------------------------------------------------
#
# Emits one line per body line, as "<id><TAB><body line>", for every case in
# the catalog's top-level `cases:` block. The id prefix keeps each body
# addressable without opening a file per case, and leaves the body text after
# the tab byte-for-byte as the catalog has it.
#
# Only the `cases:` block is read. `standards_in_scope` earlier in the file
# also holds `- id:` entries, and matching those would compare bodies that are
# not cases at all.
#
# Normalization is deliberately minimal: trailing whitespace is stripped, blank
# lines are dropped, and comment lines are dropped only at structural positions
# — at or above the case-item indent. Nothing else is touched — no attempt is
# made to unfold YAML line continuations, because that needs real YAML semantics
# and is out of scope here. The consequence is stated rather than hidden:
# re-wrapping a folded scalar reports as drift even when the meaning is
# unchanged. That direction is the safe one. A re-wrap costs a human one look at
# the diff; the opposite error is the silent under-check that produced this
# check.
#
# The indent condition on comment dropping is that same trade-off. Below the
# case-item indent a leading `#` is not necessarily a comment: inside a block
# scalar (`use_case: |`) or a multi-line double-quoted scalar it is ordinary
# text, and dropping it would let an edit to that line report clean — the one
# normalization that erred toward silence rather than noise. Deeper lines are
# compared as body text instead, so a genuine comment edit there shows as drift.
#
# Any shape the extractor cannot read with certainty is a failure, not a skip.
extract_case_bodies() {
  awk -v src="$1" '
    function die(lineno, msg) {
      printf("%s:%s: %s\n", src, lineno, msg) > "/dev/stderr"
      err = 1
      exit 1
    }

    BEGIN {
      state = 0; itemind = -1; ncases = 0; casekeys = 0
      # A single quote, as an octal escape. Writing the character itself would
      # mean breaking out of the shell quoting around this program for it.
      SQ = "\047"
    }

    # A column-0, non-blank, non-comment line either opens the cases block or,
    # once inside it, closes it.
    /^[^[:space:]#]/ {
      if ($0 ~ /^cases:[[:space:]]*(#.*)?$/) {
        casekeys++
        if (casekeys > 1) {
          die(FNR, "a second top-level cases: key; the catalog shape is not what this check parses")
        }
        state = 1
        next
      }
      if (state == 1) { state = 2 }
      next
    }

    state != 1 { next }

    # A blank line carries nothing to compare wherever it sits.
    /^[[:space:]]*$/ { next }

    {
      match($0, /^[[:space:]]*/)
      ind = RLENGTH
      rest = substr($0, ind + 1)
      isitem = (rest ~ /^-([[:space:]]|$)/)

      # A leading `#` is a comment only at a structural position: at or above
      # the case-item indent, and anywhere before the first item has fixed that
      # indent. Deeper than that it can be content — a line inside a block
      # scalar or a multi-line quoted scalar — and dropping it would hide an
      # edit to it. Those fall through and are compared as body text.
      if (rest ~ /^#/ && (itemind < 0 || ind <= itemind)) { next }

      if (itemind < 0) {
        if (!isitem) {
          die(FNR, "content inside the cases: block before the first case item; the catalog shape is not what this check parses")
        }
        itemind = ind
      }

      if (ind < itemind) {
        die(FNR, "a line inside the cases: block indented less than the case items; the catalog shape is not what this check parses")
      }

      # At the item indent, anything that is not an item start would be
      # appended to the previous case body and mis-attributed to it.
      if (ind == itemind && !isitem) {
        die(FNR, "a non-item line at the case-item indent; the catalog shape is not what this check parses")
      }

      if (ind == itemind) {
        # New case. Its id must be the first key of the item: the id is what
        # every other check keys on, and an item whose id sits further down is
        # a shape this extractor would silently mis-attribute.
        if (!match($0, /^[[:space:]]*-[[:space:]]+id:[[:space:]]*/)) {
          die(FNR, "case item does not open with an id: key; the catalog shape is not what this check parses")
        }
        raw = substr($0, RLENGTH + 1)
        sub(/[[:space:]]+$/, "", raw)

        if (substr(raw, 1, 1) == "\"") {
          if (!match(raw, /^"[^"\\]+"([[:space:]]*#.*)?$/)) {
            die(FNR, "case id is a double-quoted scalar this check will not read unambiguously (an escape, or an unterminated quote)")
          }
          id = raw
          sub(/^"/, "", id)
          sub(/"([[:space:]]*#.*)?$/, "", id)
        } else if (substr(raw, 1, 1) == SQ) {
          if (!match(raw, "^" SQ "[^" SQ "\\\\]+" SQ "([[:space:]]*#.*)?$")) {
            die(FNR, "case id is a single-quoted scalar this check will not read unambiguously (an escape, or an unterminated quote)")
          }
          id = raw
          sub("^" SQ, "", id)
          sub(SQ "([[:space:]]*#.*)?$", "", id)
        } else {
          id = raw
          sub(/[[:space:]]+#.*$/, "", id)
          sub(/[[:space:]]+$/, "", id)
        }

        # The id has to be a plain token: it names the case in every error
        # message this check emits, and it is compared as an exact string.
        if (id !~ /^[A-Za-z0-9][A-Za-z0-9._-]*$/) {
          die(FNR, "case id is not a plain token; this check compares ids as exact strings and will not guess at this one")
        }
        if (id in seen) {
          die(FNR, "duplicate case id " id "; ids key this comparison, so the second case would be invisible to it")
        }
        seen[id] = FNR
        ncases++
        curid = id
      }

      line = $0
      sub(/[[:space:]]+$/, "", line)
      printf("%s\t%s\n", curid, line)
    }

    END {
      if (err) { exit 1 }
      if (casekeys == 0) {
        printf("%s: no top-level cases: key found\n", src) > "/dev/stderr"
        exit 1
      }
      if (ncases == 0) {
        printf("%s: the cases: block parsed to zero cases; this check would compare nothing and report clean\n", src) > "/dev/stderr"
        exit 1
      }
    }
  ' "$1"
}

if ! extract_case_bodies "$PINNED_CATALOG" > "$WORK/pinned.tsv"; then
  fail "case-body drift check: could not read the case bodies out of the pinned catalog '$PINNED_CATALOG' (see the parse error above). Not reporting a clean result."
fi

if ! extract_case_bodies "$TIP_CATALOG" > "$WORK/tip.tsv"; then
  fail "case-body drift check: could not read the case bodies out of the comparison catalog '$TIP_CATALOG' (see the parse error above). Not reporting a clean result."
fi

# ---------------------------------------------------------------------------
# The registered ids to restrict the comparison to
# ---------------------------------------------------------------------------

# Tolerate blank lines and surrounding whitespace in the id list; reject
# anything else, because an id this check silently drops is a case it silently
# stops guarding.
# The `|| true` is load-bearing. grep exits 1 when it selects no lines, so on an
# id list that is entirely blank the pipeline would fail under `pipefail` and
# `set -e` would end the script right here — exit 1 with nothing printed. The
# exit code would be the right one for the wrong reason, and the next
# maintainer would get a silent red with no message to act on. Let the pipeline
# succeed and let the explicit emptiness check below do the reporting.
{ tr -d '\r' < "$REGISTERED_IDS" \
  | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
  | grep -v '^$' \
  | sort -u || true ; } > "$WORK/ids"

if [[ ! -s "$WORK/ids" ]]; then
  fail "case-body drift check: '$REGISTERED_IDS' holds no case ids. An empty id list makes this check vacuously green, which is the failure it exists to prevent."
fi

if malformed="$(grep -vE '^[A-Za-z0-9][A-Za-z0-9._-]*$' "$WORK/ids" || true)"; [[ -n "$malformed" ]]; then
  fail "case-body drift check: '$REGISTERED_IDS' holds entries that are not plain case ids: $(echo "$malformed" | tr '\n' ' '). Not reporting a clean result."
fi

case_body() {
  # $1 = stream, $2 = id
  awk -F '\t' -v id="$2" '$1 == id { print substr($0, length(id) + 2) }' "$1"
}

# ---------------------------------------------------------------------------
# Compare
# ---------------------------------------------------------------------------

drifted=0
missing_from_pin=0
absent_from_tip=0
compared=0
: > "$WORK/report"

while IFS= read -r id; do
  case_body "$WORK/pinned.tsv" "$id" > "$WORK/body.pinned"
  case_body "$WORK/tip.tsv" "$id" > "$WORK/body.tip"

  if [[ ! -s "$WORK/body.pinned" ]]; then
    # The SDK registers a case its own pinned catalog does not hold. Whatever
    # else is true, this check cannot vouch for that case, so it says so.
    echo "::error::This SDK registers conformance case '$id', which the PINNED catalog does not contain. The case-body drift check cannot compare it." >&2
    missing_from_pin=$((missing_from_pin + 1))
    continue
  fi

  if [[ ! -s "$WORK/body.tip" ]]; then
    # Removal is id-level drift and the id-set check reports it. Named here so
    # it is not mistaken for a compared-and-clean case, but not counted as body
    # drift, to keep one catalog change from being reported twice.
    echo "::warning::Conformance case '$id' is registered by this SDK and present in the pinned catalog, but absent from the comparison catalog. That is id-level drift; the alignment check is what reports it." >&2
    absent_from_tip=$((absent_from_tip + 1))
    continue
  fi

  compared=$((compared + 1))

  if ! diff -u -L "pinned/$id" -L "tip/$id" "$WORK/body.pinned" "$WORK/body.tip" > "$WORK/diff"; then
    drifted=$((drifted + 1))
    echo "::error::Pinned conformance case '$id' changed shape under the same id. This SDK's coverage for it was written against the pinned wording and nothing has verified it against the new wording." >&2
    cat "$WORK/diff" >&2
    {
      echo ""
      echo "### \`$id\`"
      echo ""
      echo '```diff'
      cat "$WORK/diff"
      echo '```'
    } >> "$WORK/report"
  fi
done < "$WORK/ids"

# A run that compared nothing is not a clean run. Reached when every registered
# id is missing from the pinned catalog, or when the id list and the catalog
# have no id in common at all — a mismatched pair of inputs, say, or an id
# source that produced plausible-looking nonsense.
if [[ "$compared" -eq 0 ]]; then
  fail "case-body drift check: not one registered case id could be compared ($(wc -l < "$WORK/ids" | tr -d ' ') ids read). The inputs do not line up; this is not a clean result."
fi

summary_head=""
if [[ "$drifted" -gt 0 ]]; then
  summary_head="## Conformance case-body drift detected"
elif [[ "$missing_from_pin" -gt 0 ]]; then
  summary_head="## Conformance case-body drift check could not verify every registered case"
fi

if [[ -n "$DRIFT_SUMMARY" && -n "$summary_head" ]]; then
  {
    echo "$summary_head"
    echo ""
    echo "Compared $compared registered case(s) between the pinned catalog and the catalog tip."
    if [[ "$drifted" -gt 0 ]]; then
      echo ""
      echo "$drifted registered case(s) changed body under an unchanged id. The id-level"
      echo "alignment check cannot see this: the id is the same, so the case looks adopted"
      echo "while its requirement has moved."
      echo ""
      echo "**Next steps:** re-read the coverage in \`$COVERAGE_DIR\` against the new"
      echo "wording. Either the coverage still holds and the pin can be bumped, or it does not"
      echo "and the registration should be downgraded to the level actually demonstrated."
      cat "$WORK/report"
    fi
    if [[ "$missing_from_pin" -gt 0 ]]; then
      echo ""
      echo "$missing_from_pin registered case(s) are absent from the pinned catalog, so their"
      echo "bodies could not be compared at all."
    fi
  } >> "$DRIFT_SUMMARY"
fi

if [[ "$drifted" -gt 0 || "$missing_from_pin" -gt 0 ]]; then
  exit 1
fi

echo "Conformance case bodies: compared $compared registered case(s) between the pinned catalog and the catalog tip; no case changed shape under an unchanged id."
if [[ "$absent_from_tip" -gt 0 ]]; then
  echo "($absent_from_tip registered case(s) are absent from the comparison catalog; the alignment check reports those.)"
fi
