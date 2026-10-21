#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

COVERAGE_DIR="$ROOT/target/coverage"
BUILD_JSON="$COVERAGE_DIR/build.json"
BINARIES="$COVERAGE_DIR/binaries.txt"
RAW_DIR="$COVERAGE_DIR/raw"
REPORT_DIR="$COVERAGE_DIR/reports"
SUMMARY="$COVERAGE_DIR/summary.txt"

rm -rf "$COVERAGE_DIR"
mkdir -p "$RAW_DIR" "$REPORT_DIR"

export RUSTFLAGS="${RUSTFLAGS:-} -C instrument-coverage"
export LLVM_PROFILE_FILE="$COVERAGE_DIR/%p-%m.profraw"

cargo test --workspace --offline --no-run --message-format=json > "$BUILD_JSON"

python3 - "$BUILD_JSON" > "$BINARIES" <<'PY'
import json
import sys

artifacts = []
with open(sys.argv[1], encoding="utf-8") as handle:
    for line in handle:
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get("reason") != "compiler-artifact":
            continue
        executable = message.get("executable")
        if executable:
            artifacts.append(executable)
for executable in sorted(set(artifacts)):
    print(executable)
PY

: > "$SUMMARY"
while IFS= read -r binary; do
    [ -x "$binary" ] || continue
    name="$(basename "$binary")"
    LLVM_PROFILE_FILE="$RAW_DIR/$name-%p.profraw" \
        "$binary" --test-threads=1 >/dev/null
    xcrun llvm-profdata merge -sparse "$RAW_DIR/$name-"*.profraw \
        -o "$REPORT_DIR/$name.profdata"
    xcrun llvm-cov report "$binary" \
        -instr-profile="$REPORT_DIR/$name.profdata" \
        --ignore-filename-regex='/.cargo/registry|/rustc/' \
        > "$REPORT_DIR/$name.txt"
    total="$(grep '^TOTAL' "$REPORT_DIR/$name.txt" || true)"
    printf '%s\n%s\n' "== $name ==" "$total" | tee -a "$SUMMARY"
done < "$BINARIES"

echo "per-binary coverage reports: $REPORT_DIR"
echo "summary: $SUMMARY"
