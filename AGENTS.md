# AGENTS.md

`devctl` is the read-only standards control plane for the local `~/dev` repo forest.

## Scope

- The public interface is the `devctl` CLI.
- Catalog policy lives under `catalog/`.
- Private operator catalog overlays live under `catalog/local/` or `DEVCTL_CATALOG_HOME`; keep them ignored.
- Archetypes and contracts are first-class policy; scanners provide evidence, not the source of intent.
- Generated standards reports live under `reports/` and remain gitignored.
- The CLI may inspect sibling repos, but V0 must not edit them.
- Contract proposals and adjudication templates must print or report only; they must not write to target repos.
- Pilot operating packets must center repo-development flow, not devctl warning counts.
- Reports must redact secret values and cite file/line evidence.

## Canonical Commands

- Check: `cargo check --workspace`
- Test: `cargo test --workspace`
- Lint: `cargo clippy --workspace --all-targets -- -D warnings`
- Format check: `cargo fmt --check`

## Guardrails

- Keep V0 read-only. Do not add repair/apply commands yet.
- Treat the sibling `cloudflare` repo as the Cloudflare control plane; do not absorb it.
- Add laws through catalog + scanner behavior together.
- Add archetypes/contracts through catalog + validation behavior together.
- Keep contract schemas typed and source-cited; validation should reject malformed catalog policy before scanners run.
- Run `devctl doctor privacy .` before publishing public branches.
- Record review decisions in `catalog/adjudications.toml`; do not hide findings without a reason.
- Never print secret values. Key names, file paths, modes, and line numbers are acceptable.
