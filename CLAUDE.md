# CLAUDE.md

`devctl` is a read-only standards control plane for the local `~/dev` repo
forest: a Rust CLI that inventories repos, audits engineering-standards drift
with file:line evidence, and plans PR-sized repair tranches — without ever
editing the target repos. V0 is report-first; repairs happen in target repos'
own PRs.

`ANCHOR.md` is the boundary doc and `NORTH_STAR.md` is the strategy doc. Read
those first when a task could broaden scope (adding apply/repair commands,
moving intent out of the catalog, or relaxing privacy). `AGENTS.md` carries the
agent rules for changing this repo.

## Core Commands

```bash
# Verification gates
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps

# Build / run the CLI
cargo build
cargo run -- inventory ~/dev
cargo run -- standards audit ~/dev --all
cargo run -- standards plan ~/dev --all --risk P0,P1

# Repeatable local standards lane
cargo run -- standards audit ~/dev --all
cargo run -- standards plan ~/dev --all --risk P0,P1
cargo run -- standards packet ~/dev --all --risk P0,P1
```

## Architecture

- `src/main.rs` is a thin binary entrypoint; `src/lib.rs` holds the whole CLI:
  the clap command surface, scanners, catalog model, report rendering, and tests.
- Command families: `inventory`, `standards`, `repo`. The `standards` family
  owns `audit`, `contracts`, `plan`, `packet`, `report`,
  `propose-contract`, and `adjudication-template`.
- `catalog/` is the source of intent: `laws.toml` (standards + maturity),
  `archetypes.toml` (repo shapes + required capabilities), `contracts/`
  (per-repo expectations), `adjudications.toml` (reviewed finding decisions),
  `workspace.toml` (pilot selection + statuses).
- Private operator truth stays out of committed catalog data; `catalog/local/`
  is reserved for ignored local-only files.
- Generated `reports/`, build `target/`, and local runtime lock state under
  `var/cargo-gate/` are ignored.

## Guardrails

- Keep V0 read-only over target repos. Do not add repair/apply commands that
  mutate siblings; proposals and templates print or report only.
- Add a law as catalog data plus scanner behavior together; add an
  archetype/contract as catalog data plus validation together. Keep contract
  schemas typed and source-cited; reject malformed catalog policy before
  scanners run.
- Never print secret values. Key names, file paths, file modes, and line numbers
  are acceptable evidence.
- Keep private truth out of the public repo. Run a manual privacy scan before
  publishing a public branch; run `standards contracts` after changing catalog
  loading or planning.
- `standards plan` must not silently return empty work when the pilot catalog
  matches no repos — warn instead.
- Record review decisions in `catalog/adjudications.toml`; do not hide findings
  without a recorded reason.
- Treat the sibling `cloudflare` repo as the Cloudflare control plane; do not
  absorb it.
