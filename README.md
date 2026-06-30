# devctl

Read-only standards control plane for the local `~/dev` repo forest.

`devctl` inventories repos, audits a small set of high-value engineering laws,
and groups findings into repair tranches. V0 is report-only: it does not edit
target repos.

## Commands

```bash
devctl inventory ~/dev --json
devctl standards audit ~/dev --pilot three-tier
devctl standards adjudication-template ~/dev --pilot three-tier --risk P0,P1
devctl standards audit ~/dev --all --json
devctl standards contracts ~/dev --pilot three-tier
devctl standards plan ~/dev --risk P0,P1
devctl standards packet ~/dev --pilot three-tier --risk P0,P1
devctl standards propose-contract ~/dev/sample-desktop-edge
devctl standards report ~/dev --pilot three-tier
devctl repo explain ~/dev/sample-desktop-edge
```

## Standards loop

V0.1 adds the review loop around the original read-only audit:

- `catalog/archetypes.toml` defines the repo shapes that make standards
  sensible.
- `catalog/contracts/` contains operator-owned repo contracts with typed command,
  Cloudflare, release, token, and artifact records. Target repos are still
  read-only.
- `catalog/local/contracts/` is ignored and may contain private operator
  contracts. Local contracts load after public contracts and override matching
  repo names without being published.
- `catalog/laws.toml` declares the active laws and their maturity.
- `catalog/adjudications.toml` records explicit review decisions by finding
  fingerprint.
- `standards contracts` compares typed repo contracts to observed repo reality.
- `standards adjudication-template` prints review stubs for unreviewed findings.
- `standards propose-contract` prints an inferred repo contract to stdout only.
- `standards plan` excludes findings adjudicated as `accepted-exception`,
  `false-positive`, or `law-needs-work`, then groups remaining work by
  repo/law/requirement so tranches are PR-sized.
- `standards packet` writes the pilot operating packet: contract proposals,
  adjudication stubs, risk-scoped tranches, and ordered next actions.
- `standards report` writes JSON and Markdown snapshots under `reports/`.

Generated reports are ignored by git. They are evidence artifacts, not source
policy.

The repo development flow is the center of the system. Contracts and archetypes
define intent; `devctl` is the read-only instrument panel that observes drift,
proposes contracts, and packages repair work.

## Verification

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
