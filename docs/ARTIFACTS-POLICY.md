# Artifacts Policy

`devctl` is report-first. Runtime and evidence files are intentionally local
artifacts, not source policy.

## Classified Paths

| Path | Classification | Git posture |
| --- | --- | --- |
| `reports/` | Generated standards reports and operator review packets. | Ignored. Regenerate from `devctl standards report` or `devctl standards packet`. |
| `var/` | Local runtime state, cargo-gate logs, and transient command receipts. | Ignored. Machine-local evidence only. |
| `target/` | Rust build and documentation output. | Ignored. Regenerate with Cargo. |

Tracked policy belongs under `catalog/`. Generated reports and runtime receipts
must not become the source of intent, and they must not contain secret values.
