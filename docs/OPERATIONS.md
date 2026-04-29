# devctl Operations

This runbook turns `devctl` into a repeatable standards loop.

The goal is not to make `devctl` smarter than the repos. The goal is to make
repo drift visible, reviewable, and small enough to repair in normal PRs.

## Weekly Lane

Run the lane from the `devctl` repo:

```bash
./scripts/standards-loop.sh ~/dev
```

The script runs:

1. `doctor catalog`
2. `doctor privacy`
3. `inventory`
4. `standards contracts`
5. `standards audit`
6. `standards plan`
7. `standards packet`

JSON snapshots go under `reports/operations/`, which is ignored by git.

## Scope

Default scope is `--all` because a sanitized public catalog may not contain real
pilot repo names.

Use an explicit pilot after a private overlay is loaded:

```bash
DEVCTL_SCOPE=pilot DEVCTL_PILOT=three-tier ./scripts/standards-loop.sh ~/dev
```

If `doctor catalog` says the pilot matched zero repos, do not trust pilot plans.
Load the private overlay or intentionally use `--all`.

## Private Catalog Setup

Public catalog files stay generic. Real workspace truth belongs in ignored local
catalogs:

```bash
mkdir -p catalog/local/contracts
cp examples/local-catalog/workspace.toml catalog/local/workspace.toml
cp examples/local-catalog/contracts/product-web.toml catalog/local/contracts/product-web.toml
```

Then edit the ignored copies with real repo names, statuses, and contracts.

Verify:

```bash
devctl doctor catalog ~/dev
devctl standards contracts ~/dev --pilot three-tier
devctl standards plan ~/dev --pilot three-tier --risk P0,P1
```

## Triage Order

Handle findings in this order:

1. P0 token or file-permission findings
2. missing repo contracts for active repos
3. release proof gaps
4. Cloudflare mutation posture gaps
5. command classification and artifact boundary gaps

Every repair should be small enough to review as one target-repo PR.

## Adjudication

Do not suppress noisy findings informally.

- True issue: fix it in the target repo.
- Intentional exception: record an adjudication with reason, owner, and expiry.
- Bad law behavior: adjust the law or scanner with a test.
- Missing intent: add or update the private contract.

## PR Proof

A standards repair PR should say:

- which `devctl` finding IDs it addresses
- which command proves the fix
- whether any adjudication or contract changed
- which evidence directory or report snapshot was reviewed

`devctl` remains read-only. Target repos carry the actual changes.
