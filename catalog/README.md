# devctl Catalog

The catalog is the policy layer for `devctl`.

Scanners describe what exists. Catalogs describe what should exist. Findings are
useful only when those two views are kept separate.

## Files

```text
catalog/
|-- workspace.toml       # pilot repos, repo statuses, public sample workspace
|-- laws.toml            # standards and maturity
|-- archetypes.toml      # reusable repo shapes
|-- adjudications.toml   # reviewed finding decisions
`-- contracts/           # repo-specific expectations
```

## Workspace Catalog

`workspace.toml` defines the active pilot list and known repo status values.

The public file uses neutral sample repo names. Real operator workspace names
belong in an ignored local overlay.

## Laws

`laws.toml` defines the standards that scanners can report against. A law should
be added with scanner behavior and tests in the same change.

V0 laws cover:

- Cloudflare mutation lanes
- token handling
- command and verification surfaces
- release proof
- artifact boundaries

## Archetypes

`archetypes.toml` defines reusable repo shapes such as Rust workspaces,
Cloudflare products, and generic active repos.

Archetypes are intentionally small. They should express requirements that are
shared by more than one repo, not one-off local taste.

## Contracts

`contracts/*.toml` defines repo-specific expectations:

- canonical commands
- Cloudflare posture and surfaces
- token policy
- release lanes and evidence
- artifact classifications

Contract filenames must match the declared `repo` value. Public contracts should
use neutral sample repo names. Private contracts belong in local overlays.

## Adjudications

`adjudications.toml` records reviewed findings by fingerprint. Use it to mark a
finding as:

- `true-positive`
- `accepted-exception`
- `false-positive`
- `law-needs-work`

Do not hide findings without a reason. Exceptions should have an owner and an
expiry when possible.

## Private Overlays

Private operator catalog overlays can live in either location:

```bash
catalog/local/
DEVCTL_CATALOG_HOME=/path/to/private/catalog
```

Overlay behavior:

- a local `workspace.toml` can replace the public pilot list
- local repo statuses override public repo statuses
- local contracts override public contracts for the same repo
- local overlays are ignored by git

Use `devctl doctor catalog <workspace>` to confirm that the expected overlay is
loaded before trusting pilot plans.

Neutral templates live under `examples/local-catalog/`. Copy them into
`catalog/local/` or an external private catalog directory, then replace the
sample repo names with local workspace truth in the ignored copy.
