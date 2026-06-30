# devctl Anchor

## Purpose

This file captures the truths that should stay stable while `devctl` evolves.
If a proposal conflicts with these anchors, the burden is on the proposal.

## Product Anchors

- `devctl` is a read-only standards control plane for the local `~/dev` repo
  forest, not a repair tool and not a CI service.
- It inventories repos, audits standards drift, explains repos, proposes
  contracts, and plans PR-sized repair work — and stops there.
- V0 must not edit, apply, or repair target repos. Repairs happen in the target
  repos' own PRs.
- The catalog defines intent; scanners provide evidence. Evidence is never the
  source of truth about what a repo *should* be.

## Architectural Anchors

- The public interface is the `devctl` CLI. `src/main.rs` is a thin entrypoint;
  `src/lib.rs` carries the clap surface, scanners, catalog model, reports, and
  tests.
- Command families are `inventory`, `standards`, and `repo`. The `standards`
  family owns `audit`, `contracts`, `plan`, `packet`, `report`,
  `propose-contract`, and `adjudication-template`.
- Intent lives in `catalog/`: `laws.toml`, `archetypes.toml`, `contracts/`,
  `adjudications.toml`, `workspace.toml`. Private operator truth stays out of
  committed catalog data; `catalog/local/` is reserved for ignored local files.
- Contract schemas stay typed and source-cited. Validation rejects malformed
  catalog policy before scanners run.
- A new law lands as catalog data plus scanner behavior together; a new
  archetype/contract lands as catalog data plus validation together.

## Safety Anchors

- Never edit, apply, or repair a target repo from V0.
- Never print secret values. Key names, file paths, file modes, and line numbers
  are acceptable evidence; secret contents are not.
- Never commit private operator truth (real repo names, home paths, emails) to
  the public repo. Sanitized sample data and ignored overlays only.
- Contract proposals and adjudication templates print or report only; they never
  write into target repos.
- `standards plan` must not silently return empty work when the selected pilot
  catalog matches no repos — warn instead.

## Operational Anchors

- Canonical verification: `cargo fmt --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `cargo doc --workspace --no-deps`.
- Manually check private paths, emails, and operator-only names before
  publishing a public branch.
- Run `standards contracts` after changing catalog loading or planning
  behavior.
- Record review decisions in `catalog/adjudications.toml`; do not hide findings
  without a recorded reason.
- Use `standards audit`, `standards plan`, `standards packet`, and a manual
  privacy scan as the repeatable local lane.

## Decision Questions

Before changing code, ask:

1. Does this keep `devctl` read-only over target repos?
2. Does intent stay in the catalog and evidence stay in scanners?
3. Are findings redacted, file:line-cited, and free of secret values?
4. Does the public repo stay publishable, with private truth in ignored
   overlays?
5. Can the change be verified through the canonical cargo gates and a manual
   privacy scan?

If the answer to any of those is "no", the change probably needs to be smaller
or differently shaped.
