#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Upstream's two suites, both built by mayhem/build.sh with the project's normal flags:
#   ./test.out   — tests/test.c, the main suite (vectors from the regenerated tests/vectors.h for every
#                  primitive incl. AEAD decrypt, EdDSA/Ed25519ph check, parallel Argon2, plus
#                  roundtrip/forgery/property checks), ending with "All tests OK!".
#   ./tis-ci.out — tests/tis-ci.c, the known-answer suite over the committed tests/tis-ci-vectors.h.
# Each prints a marker as each check runs and exit(1)s on the first failing check, so a check
# PASSES iff its own marker was printed and the run got past it (a later marker, or a clean exit
# with no assertion failure). A neutered binary prints nothing → every check fails.
#
# Markers in execution order. "@vec:" = a "\t<name>" line printed BEFORE the check runs;
# "@ok:"  = an "OK: <name>" line printed AFTER the check succeeded;
# "@end:" = the suite's final success line (passes iff printed and the run was clean);
# "@silent:" = a check that prints nothing (passes iff the run reached the next marker).
TEST_CHECKS=(
  @vec:crypto_wipe @vec:crypto_verify16 @vec:crypto_verify32 @vec:crypto_verify64
  @vec:chacha20 "@vec:Chacha20 (ctr)" "@vec:Chacha20 (nullptr == zeroes)" "@vec:Chacha20 (output == input)"
  @vec:ietf_chacha20 "@vec:ietf Chacha20 (ctr)" @vec:xchacha20 "@vec:XChacha20 (ctr)"
  @vec:hchacha20 "@vec:HChacha20 (overlap)" @vec:aead_ietf @vec:aead_8439
  "@vec:aead (roundtrip)" "@vec:aead incr (roundtrip)"
  @vec:poly1305 "@vec:Poly1305 (incremental)" "@vec:Poly1305 (overlapping i/o)"
  @vec:blake2b "@vec:BLAKE2b (zero_input)" "@vec:BLAKE2b (incremental)" "@vec:BLAKE2b (overlapping i/o)"
  @vec:sha512 @vec:sha512_hmac @vec:sha512_hkdf "@vec:SHA-512 (incremental)" "@vec:SHA-512 (overlapping i/o)"
  "@vec:HMAC SHA-512 (incremental)" "@vec:HMAC SHA-512 (overlapping i/o)"
  @vec:argon2 "@vec:Argon2 (overlapping i/o)" "@vec:Argon2 (parallel API)"
  @vec:x25519 @vec:x25519_pk "@vec:x25519 1" "@vec:x25519 1K" "@vec:x25519 (overlapping i/o)"
  @vec:x25519_inverse "@vec:x25519 inverse (overlapping i/o)"
  "@vec:EdDSA (scalarbase)" @vec:edDSA @vec:edDSA_pk "@vec:EdDSA (roundtrip)" "@vec:EdDSA (random)"
  "@vec:EdDSA (overlap)" @vec:ed_25519 @vec:ed_25519_pk @vec:ed_25519_check @vec:ed_25519ph
  @vec:elligator_dir "@vec:elligator direct (msb)" "@vec:elligator direct (overlapping i/o)"
  @vec:elligator_inv "@vec:elligator inverse (overlapping i/o)" "@vec:elligator x25519"
  "@vec:elligator key pair" "@vec:elligator key pair (overlapping i/o)" "@vec:X25519 <-> EdDSA"
  "@end:All tests OK!"
)
TIS_CHECKS=(
  @vec:chacha20 @vec:ietf_chacha20 @vec:hchacha20 @vec:xchacha20 @vec:poly1305 @vec:aead_ietf
  @vec:blake2b @vec:sha512 @vec:sha512_hmac @vec:sha512_hkdf @vec:argon2 @vec:x25519 @vec:edDSA
  @vec:edDSA_pk @vec:ed_25519 @vec:ed_25519_check @vec:elligator_dir @vec:elligator_inv
  @vec:crypto_wipe @silent:eddsa_x25519 "@ok:x25519 dirty" @ok:x25519_inverse
  @ok:crypto_verify16 @ok:crypto_verify32 @ok:crypto_verify64
)

passed=0; failed=0
CHECKS=(); out=""; clean=0

seen() {  # seen <index> → 0 if the marker of check <index> is in the output
  local c="${CHECKS[$1]}" kind name
  kind="${c%%:*}"; name="${c#*:}"
  case "$kind" in
    @vec)    grep -qFx "$(printf '\t%s' "$name")" <<<"$out" ;;
    @ok)     grep -qFx "OK: $name" <<<"$out" ;;
    @end)    grep -qFx "$name" <<<"$out" ;;
    @silent) return 1 ;;
  esac
}
reached_after() {  # reached_after <index> → 0 if any later marker was printed
  local j
  for ((j = $1 + 1; j < ${#CHECKS[@]}; j++)); do seen "$j" && return 0; done
  return 1
}

# run_suite <runner> <label> <checks...> — runs one suite and adds its checks to passed/failed.
run_suite() {
  local runner="$SRC/$1" label="$2" rc i c ok f0="$failed"; shift 2
  CHECKS=("$@")
  if [ ! -x "$runner" ]; then
    echo "test.sh: $runner missing — mayhem/build.sh should have built it" >&2
    failed=$((failed + ${#CHECKS[@]})); return
  fi
  out="$("$runner" 2>&1)"; rc=$?
  printf '%s\n' "$out"
  clean=0
  [ "$rc" -eq 0 ] && ! grep -q 'Assert failure\|FAILED\|FAILURE' <<<"$out" && clean=1
  for i in "${!CHECKS[@]}"; do
    c="${CHECKS[$i]}"; ok=0
    case "${c%%:*}" in
      @ok)     seen "$i" && ok=1 ;;
      @vec)    seen "$i" && { reached_after "$i" || [ "$clean" -eq 1 ]; } && ok=1 ;;
      @end)    seen "$i" && [ "$clean" -eq 1 ] && ok=1 ;;
      @silent) reached_after "$i" && ok=1 ;;
    esac
    if [ "$ok" -eq 1 ]; then passed=$((passed + 1)); else failed=$((failed + 1)); echo "FAIL: $label: ${c#*:}"; fi
  done
  [ "$clean" -eq 1 ] || { echo "$label exited $rc or reported a failure"; [ "$failed" -gt "$f0" ] || failed=$((failed + 1)); }
}

run_suite test.out   test   "${TEST_CHECKS[@]}"
run_suite tis-ci.out tis-ci "${TIS_CHECKS[@]}"

emit_ctrf "monocypher-tests" "$passed" "$failed" 0
