#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es).
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

TARGETS="aead eddsa ed25519 argon2 blake2b poly1305 x25519 chacha20 sha512"
OBJ="$SRC/mayhem/build"          # gitignored (mayhem/.gitignore), recreated on every run
mkdir -p "$OBJ"
INC="-I$SRC/src -I$SRC/src/optional -I$SRC/mayhem/harnesses"

# 1) The library itself (two translation units, no build system needed), instrumented, and the
#    harnesses. Every object is compiled twice: with SanitizerCoverage (-fsanitize=fuzzer-no-link,
#    for the libFuzzer binaries) and without it (for the standalone reproducers, which link no
#    fuzzer runtime and so must also build with an empty SANITIZER_FLAGS).
COV_FLAGS="${LIB_FUZZING_ENGINE/fuzzer/fuzzer-no-link}"
mkdir -p "$OBJ/fuzz" "$OBJ/standalone"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OBJ/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"
for kind in fuzz standalone; do
  extra=""; [ "$kind" = fuzz ] && extra="$COV_FLAGS"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $extra -O1 $INC -c src/monocypher.c -o "$OBJ/$kind/monocypher.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $extra -O1 $INC -c src/optional/monocypher-ed25519.c -o "$OBJ/$kind/monocypher-ed25519.o"
  for t in $TARGETS; do
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS $extra -O1 $INC -c "mayhem/harnesses/fuzz_$t.c" -o "$OBJ/$kind/fuzz_$t.o"
  done
done

# 2) One libFuzzer binary + one standalone reproducer per harness.
for t in $TARGETS; do
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OBJ/fuzz/fuzz_$t.o" \
       "$OBJ/fuzz/monocypher.o" "$OBJ/fuzz/monocypher-ed25519.o" "$OBJ/lsan_off.o" -o "$SRC/fuzz_$t"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OBJ/standalone_main.o" "$OBJ/standalone/fuzz_$t.o" \
       "$OBJ/standalone/monocypher.o" "$OBJ/standalone/monocypher-ed25519.o" "$OBJ/lsan_off.o" \
       -o "$SRC/fuzz_$t-standalone"
done

# 3) Upstream's two test suites, with the project's normal flags, through upstream's own makefiles.
#    -march=native is dropped from upstream's default CFLAGS so the binaries are host-independent.
#    - tests/test.c, the main suite (every primitive's vectors incl. AEAD decrypt, EdDSA/Ed25519ph
#      check, parallel Argon2, plus roundtrip/forgery/property checks). Its tests/vectors.h is
#      gitignored, so regenerate it here as upstream CI does (`cd tests/gen && make`): offline and
#      deterministic (fixed seeds), using libsodium + python3-cryptography from the image and the
#      vendored tests/externals/ed25519-donna.
#    - tests/tis-ci.c, the known-answer suite over the committed tests/tis-ci-vectors.h.
make -C tests/gen -j"$MAYHEM_JOBS" CC="$CC -std=c99"
make test.out tis-ci.out CC="$CC -std=c99" CFLAGS="-pedantic -Wall -Wextra -O2 $COVERAGE_FLAGS"
