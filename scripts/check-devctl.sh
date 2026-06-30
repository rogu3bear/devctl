#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

FOREST_ROOT="${DEVCTL_FOREST_ROOT:-${1:-${HOME}/dev}}"
CONTRACTS_OUT="${TMPDIR:-/tmp}/devctl-contracts-check.json"
PLAN_OUT="${TMPDIR:-/tmp}/devctl-plan-check.json"

cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps

if [[ -d "${FOREST_ROOT}" ]]; then
  cargo run -- standards contracts "${FOREST_ROOT}" --all --json >"${CONTRACTS_OUT}"
  cargo run -- standards plan "${FOREST_ROOT}" --all --risk P0,P1 --json >"${PLAN_OUT}"
else
  printf 'devctl check: skipping forest readback; root not found: %s\n' "${FOREST_ROOT}" >&2
fi
