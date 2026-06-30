# devctl North Star

## Intent

`devctl` exists to make engineering-standards drift across a local repo forest
visible and actionable without ever touching the target repos.

It answers three questions about a workspace root like `~/dev`:

- What repos exist here, and what shape are they?
- Which engineering standards are drifting, with file:line evidence?
- What PR-sized repair tranches should happen next, and in what risk order?

V0 is deliberately report-first. It inventories, audits, explains, proposes, and
plans. The actual repairs happen in the target repos' own PRs, by hand.

## Core Promise

- Stay read-only over target repos. `devctl` reads and reports; it never edits,
  applies, or repairs a sibling repo.
- Treat the catalog as the source of intent and scanners as the source of
  evidence. Findings cite file:line; intent comes from declared policy.
- Never print secret values. Key names, file paths, file modes, and line
  numbers are acceptable evidence; secret contents are not.
- Keep the public repo publishable. Real operator workspace truth lives in
  ignored private overlays, not in committed sample data.
- Make planning honest. `standards plan` must not silently return empty work
  when the selected pilot catalog matches no repos.

## Product Shape Today

The public interface is the `devctl` CLI (`src/lib.rs`, thin `src/main.rs`
entry). It groups into three command families:

1. `inventory <root>` — walk the forest, discover repos, report their shape.
2. `standards {audit, contracts, plan, packet, report, propose-contract,
   adjudication-template}` — compare declared contracts against observed
   reality, collect findings, and group them into reviewable, PR-sized work.
3. `repo explain <path>` — explain a single repo's shape and standing.

The catalog under `catalog/` defines intent: `laws.toml`, `archetypes.toml`,
`contracts/`, `adjudications.toml`, and `workspace.toml`. Private operator
truth stays out of committed catalog data; `catalog/local/` is reserved for
ignored local-only files. Generated `reports/` and `target/` are ignored too.

## What "Good" Looks Like

- An operator confirms the intended catalog scope, then runs `inventory`,
  `standards contracts`, and `standards audit` to gather file:line evidence.
- True positives and accepted exceptions are recorded in
  `catalog/adjudications.toml` instead of silently dropped.
- `standards plan` / `standards packet` emit PR-sized repair tranches ordered by
  severity (P0..P3), repo, and law — centered on repo-development flow, not on
  devctl's own warning counts.
- The public branch is manually checked for private paths, emails, and
  operator-only names before it is pushed.

## Scope Boundaries

- Policy/intent belongs in `catalog/`; evidence-gathering belongs in scanners.
- Add a law through catalog data *and* scanner behavior together; add an
  archetype/contract through catalog data *and* validation together.
- The sibling `cloudflare` repo is the Cloudflare control plane. `devctl` does
  not absorb it.
- Private operator truth belongs outside committed sample catalog data.

## Decision Filter

Prefer changes that increase trust in the standards loop:

- stronger file:line evidence and clearer redaction
- typed, source-cited contract schemas that reject malformed policy early
- explicit planning scope (no silent zero-repo plans)
- cleaner separation between public machinery and private overlays

## Anti-Goals

- Adding repair/apply commands that mutate target repos in V0.
- Printing secret values, or leaking private repo names into the public repo.
- Letting scanners become the source of intent instead of the catalog.
- Absorbing the `cloudflare` control plane or other repos' responsibilities.
- Producing plans that center devctl warning counts over real repo-dev flow.
