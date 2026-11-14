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
devctl standards plan ~/dev --all --risk P0,P1
devctl standards packet ~/dev --pilot three-tier --risk P0,P1
devctl standards propose-contract ~/dev/sample-desktop-edge
devctl standards propose-contract ~/dev/sample-desktop-edge --json
devctl standards report ~/dev --pilot three-tier
devctl repo explain ~/dev/sample-desktop-edge
```

## Standards loop

Catalog checks are advisory interpretations of `mlnavigator-ai/standards`, not
independent rule authority. Each law names stable standard IDs and a selected
standards revision. Local equivalents and adopted repository guidance retain
their meaning. See [standards alignment](docs/STANDARDS-ALIGNMENT.md).

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
- `standards propose-contract` prints a catalog-shaped TOML draft to stdout
  only, with local proposal metadata such as absolute paths stripped. Add
  `--json` when you need the full evidence/proposal payload.
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

Catalogs are relocatable: put public `catalog/` beside a distributed executable,
or select `devctl --catalog-root /path/to/catalog inventory /path/to/forest --json`.
Source development uses `cargo run -- --catalog-root ./catalog ...`. Runtime
lookup never uses the build machine's source directory; missing inputs fail.

Direct CLI use retains the selected catalog's `local/contracts` overlay when
present. `--no-private-contracts` disables it; `--contracts-overlay /private/path`
selects a separate existing directory. These are read-only inputs. Component
exports exclude all private overlays and reports. Invalid contract errors omit
source values. MLN's audit route disables private loading unless explicitly
selected. Report/packet commands still write outputs, under current `./reports`
or `--out`, and do not write into a catalog merely because the binary moved.

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
