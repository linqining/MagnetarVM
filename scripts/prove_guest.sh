#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

./scripts/build_guest.sh
cargo run --offline -p magnetar-testkit --example prove_guest -- target/guest/hello.elf "${1:-64}"
