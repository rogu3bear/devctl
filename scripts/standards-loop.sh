#!/usr/bin/env bash
set -euo pipefail

workspace_root="${1:-${DEVCTL_WORKSPACE_ROOT:-$HOME/dev}}"
risk="${DEVCTL_RISK:-P0,P1}"
report_dir="${DEVCTL_REPORT_DIR:-reports/operations}"
scope_value="${DEVCTL_SCOPE:---all}"
pilot_value="${DEVCTL_PILOT:-three-tier}"

case "$scope_value" in
  --all|all)
    scope_args=(--all)
    scope_slug="all"
    ;;
  --pilot|pilot)
    scope_args=(--pilot "$pilot_value")
    scope_slug="pilot-$pilot_value"
    ;;
  "")
    scope_args=()
    scope_slug="default"
    ;;
  *)
    echo "unknown DEVCTL_SCOPE: $scope_value" >&2
    echo "use DEVCTL_SCOPE=--all or DEVCTL_SCOPE=pilot" >&2
    exit 2
    ;;
esac

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
run=(cargo run --quiet --)
snapshot_dir="$report_dir/$stamp-$scope_slug"

mkdir -p "$snapshot_dir"

echo "devctl standards loop"
echo "workspace_root=$workspace_root"
echo "scope=${scope_args[*]:-default}"
echo "risk=$risk"
echo "snapshot_dir=$snapshot_dir"

"${run[@]}" doctor catalog "$workspace_root" --json \
  > "$snapshot_dir/doctor-catalog.json"
"${run[@]}" doctor privacy . --json \
  > "$snapshot_dir/doctor-privacy.json"
"${run[@]}" inventory "$workspace_root" --json \
  > "$snapshot_dir/inventory.json"
"${run[@]}" standards contracts "$workspace_root" "${scope_args[@]}" --json \
  > "$snapshot_dir/contracts.json"
"${run[@]}" standards audit "$workspace_root" "${scope_args[@]}" --json \
  > "$snapshot_dir/audit.json"
"${run[@]}" standards plan "$workspace_root" "${scope_args[@]}" --risk "$risk" --json \
  > "$snapshot_dir/plan.json"
"${run[@]}" standards packet "$workspace_root" "${scope_args[@]}" --risk "$risk" --out "$report_dir" --json \
  > "$snapshot_dir/packet.json"

echo "wrote $snapshot_dir"
