# devctl

`devctl` is a read-only standards control plane for a local repo forest.

It answers three questions:

- What repos exist here, and what shape are they?
- Which engineering standards are drifting?
- What PR-sized repair tranches should happen next?

V0 is intentionally report-first. It inventories, audits, explains, proposes,
and plans. It does not edit target repos.

## Mental Model

`devctl` has three layers:

- **Catalogs define intent.** Laws, archetypes, contracts, and adjudications live
  under `catalog/`.
- **Scanners gather evidence.** The CLI walks repos, records file:line evidence,
  and never prints secret values.
- **Reports shape action.** Plans, packets, reports, and contract proposals group
  findings into reviewable work.

The public repo carries reusable standards machinery and neutral sample catalog
data. Real operator workspace truth belongs in ignored private overlays under
`catalog/local/` or an external `DEVCTL_CATALOG_HOME`.

## Repo Map

```text
.
|-- AGENTS.md                 # rules for agents changing this repo
|-- README.md                 # operator and contributor orientation
|-- Cargo.toml                # Rust CLI crate
|-- docs/
|   `-- OPERATIONS.md         # weekly standards loop runbook
|-- examples/
|   `-- local-catalog/        # safe private-overlay templates
|-- scripts/
|   `-- standards-loop.sh     # repeatable local standards lane
|-- src/
|   |-- main.rs               # thin binary entrypoint
|   `-- lib.rs                # CLI, scanners, catalogs, reports, tests
`-- catalog/
    |-- README.md             # catalog model and editing guide
    |-- workspace.toml        # public sample workspace catalog
    |-- laws.toml             # standard definitions and maturity
    |-- archetypes.toml       # repo shapes and required capabilities
    |-- adjudications.toml    # reviewed finding decisions
    `-- contracts/            # public sample repo contracts
```

Generated reports live under `reports/` and build outputs live under `target/`.
Both are ignored.

## First Run

Use the doctor commands before trusting plans:

```bash
devctl doctor catalog ~/dev
devctl doctor privacy .
```

`doctor catalog` tells you whether a private overlay is loaded, whether the
active pilot catalog matches the selected workspace root, and how many contracts
are active. It reports counts and sanitized root labels, not private repo names.

`doctor privacy` scans the public repo for absolute home paths, email addresses,
and optional local private patterns.

Then inspect the workspace:

```bash
devctl inventory ~/dev
devctl standards audit ~/dev --all
devctl standards plan ~/dev --all --risk P0,P1
```

If `standards plan ~/dev --risk P0,P1` returns a zero-repo pilot warning, load a
private catalog overlay or use `--all` intentionally.

For the repeatable local lane, run:

```bash
./scripts/standards-loop.sh ~/dev
```

See `docs/OPERATIONS.md` for the triage loop.

## Command Guide

```bash
devctl inventory ~/dev --json
devctl repo explain ~/dev/sample-web-product

devctl standards audit ~/dev --pilot three-tier
devctl standards audit ~/dev --all --json
devctl standards contracts ~/dev --pilot three-tier
devctl standards plan ~/dev --risk P0,P1
devctl standards plan ~/dev --all --risk P0,P1
devctl standards adjudication-template ~/dev --pilot three-tier --risk P0,P1
devctl standards propose-contract ~/dev/sample-web-product
devctl standards packet ~/dev --pilot three-tier --risk P0,P1
devctl standards report ~/dev --pilot three-tier

devctl doctor catalog ~/dev
devctl doctor privacy .
```

## Standards Loop

The normal operating loop is:

1. Run `doctor catalog` and `doctor privacy`.
2. Run `inventory` to confirm repo discovery.
3. Run `standards contracts` to compare declared intent with observed reality.
4. Run `standards audit` to collect file:line findings.
5. Run `standards adjudication-template` to review true positives and
   exceptions.
6. Run `standards plan` or `standards packet` to produce PR-sized repair work.
7. Repair target repos manually in their own PRs.

`devctl` stays read-only through this loop. The target repos carry the actual
repairs.

## Catalogs

The catalog is the source of intent:

- `catalog/laws.toml` declares standards and maturity.
- `catalog/archetypes.toml` describes repo shapes and required capabilities.
- `catalog/contracts/` declares repo-specific expectations.
- `catalog/adjudications.toml` records reviewed finding decisions.
- `catalog/workspace.toml` selects pilot repos and status values.

Private overlays can replace pilot lists and override matching repo statuses or
contracts without committing private repo names to the public repo.

See `catalog/README.md` for the editing model and `examples/local-catalog/` for
safe templates.

## Output Rules

- JSON output uses `schema_version = "0.1.0"`.
- Findings include file:line evidence when available.
- Human output sorts actionable work by severity, repo, and law.
- Secret values are never printed. Key names, file paths, file modes, and line
  numbers are acceptable evidence.
- Publication checks should run `doctor privacy` before pushing public branches.

## Verification

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps
```
