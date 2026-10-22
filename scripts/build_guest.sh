#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT/target/guest"
GUEST_DIR="$ROOT/guests/hello"

if ! command -v zig >/dev/null 2>&1; then
    echo "error: zig is required to build the guest ELF" >&2
    echo "install it from https://ziglang.org/download/ and rerun this script" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

zig cc \
    -target riscv64-freestanding \
    -mcpu=generic_rv64-c \
    -mabi=lp64 \
    -O2 \
    -nostdlib \
    -ffreestanding \
    -fno-builtin \
    -fno-stack-protector \
    -mno-relax \
    -Wl,-T,"$GUEST_DIR/link.ld" \
    -Wl,--build-id=none \
    -o "$OUT_DIR/hello.elf" \
    "$GUEST_DIR/start.S" \
    "$GUEST_DIR/main.c"

echo "built $OUT_DIR/hello.elf"
