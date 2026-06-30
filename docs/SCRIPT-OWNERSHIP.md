# Script Ownership

This repository is a read-only standards control plane. Scripts must verify the
local tool or gather bounded evidence; they must not mutate sibling repos.

## Gated Verification

| Script | Owner | Purpose | Mutation boundary |
| --- | --- | --- | --- |
| `scripts/check-devctl.sh` | devctl maintainers | Runs formatting, lint, tests, docs, and optional forest planning readback. | Read-only over target repos. Writes only local build output and temporary JSON under `${TMPDIR:-/tmp}`. |

The optional forest readback uses `DEVCTL_FOREST_ROOT`, an argv root, or
`${HOME}/dev`. It is evidence only: contracts and plans are printed to temporary
files and do not edit target repositories.
