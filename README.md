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
devctl standards plan ~/dev --all --risk P0,P1
devctl standards packet ~/dev --pilot three-tier --risk P0,P1
devctl standards propose-contract ~/dev/sample-desktop-edge
devctl standards report ~/dev --pilot three-tier
devctl repo explain ~/dev/sample-desktop-edge
devctl doctor catalog ~/dev
devctl doctor privacy .
```

## Standards loop

V0.1 adds the review loop around the original read-only audit:

- `catalog/archetypes.toml` defines the repo shapes that make standards
  sensible.
- `catalog/contracts/` contains operator-owned repo contracts with typed command,
  Cloudflare, release, token, and artifact records. Target repos are still
  read-only.
- `catalog/local/` or `DEVCTL_CATALOG_HOME` can provide ignored private operator
  overlays. Local overlay values replace public pilot lists and override matching
  repo statuses/contracts without making private repo names public.
- `catalog/laws.toml` declares the active laws and their maturity.
- `catalog/adjudications.toml` records explicit review decisions by finding
  fingerprint.
- `standards contracts` compares typed repo contracts to observed repo reality.
- `standards adjudication-template` prints review stubs for unreviewed findings.
- `standards propose-contract` prints an inferred repo contract to stdout only.
- `standards plan` excludes findings adjudicated as `accepted-exception`,
  `false-positive`, or `law-needs-work`, then groups remaining work by
  repo/law/requirement so tranches are PR-sized. It accepts the same `--pilot`
  and `--all` scope controls as audit and warns when the selected scope matches
  zero repos.
- `standards packet` writes the pilot operating packet: contract proposals,
  adjudication stubs, risk-scoped tranches, and ordered next actions.
- `standards report` writes JSON and Markdown snapshots under `reports/`.

Generated reports are ignored by git. They are evidence artifacts, not source
policy.

The repo development flow is the center of the system. Contracts and archetypes
define intent; `devctl` is the read-only instrument panel that observes drift,
proposes contracts, and packages repair work.

## Privacy Gate

Before publishing public branches, run:

```bash
devctl doctor catalog ~/dev
devctl doctor privacy .
```

The catalog doctor reports whether a private local overlay is loaded, how many
pilot repos/contracts are active, and whether the selected workspace root
matches the active pilot catalog. It intentionally reports counts and sanitized
root labels, not private repo names.

The privacy doctor scans tracked-style source, docs, catalogs, and generated
reports while ignoring `.git`, `target`, and `node_modules`. It flags absolute
home paths and email addresses by default. Set `DEVCTL_PRIVACY_PATTERNS` to a
comma-separated list of additional regular expressions for local private names
or domains.

## Verification

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
