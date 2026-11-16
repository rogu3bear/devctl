# Canonical standards and advisory catalog checks

The catalog records interpretations and selected operator contracts. Canonical
shared rules stay in `mlnavigator-ai/standards`; repository adoption, current
human grants and local equivalents retain authority. No finding authorizes
repair, publication, credential use or a policy exception.

`catalog/laws.toml` identifies standards revision
`1126724a785ee2e01ee3d5668b8e3ecefe6d1f7b`. Its source is
https://github.com/mlnavigator-ai/standards/tree/1126724a785ee2e01ee3d5668b8e3ecefe6d1f7b/standards.
Findings include declared standard IDs, source revision and law maturity.
Attribution does not prove applicability or native enforcement.

The law catalog schema advances to `0.2.0` because canonical source and reference
fields are required. Select the matching catalog with the new binary; older law
catalogs fail rather than receiving invented source attribution. Contract,
archetype and JSON report schemas remain `0.1.0`; private contract schemas and
adjudication records are unchanged.

| Check | Canonical basis | Interpretation limit |
| --- | --- | --- |
| Cloudflare mutation | `STD:AUTH.BOUNDARY`, `STD:AUTH.NO_LAUNDERING` | Possible raw lanes need owner review; the Cloudflare authority owns execution and exceptions. |
| Token handling | `STD:AUTH.BOUNDARY`, `STD:CODE.SCOPE` | Redacted evidence and operator token declarations confer no credential authority. |
| Commands and verification | `STD:VERIFY.DIRECT`, `STD:VERIFY.COMPLETE` | Declared commands are not executed checks or proof of sufficiency. |
| Release proof | `STD:VERIFY.COMPLETE`, `STD:AUTH.BOUNDARY` | Evidence-bound owner review; scripts and files do not grant permission. |
| Artifact boundary | `STD:CODE.SCOPE`, `STD:VERIFY.DIRECT` | Observed paths are not cleanup candidates. |
| Repository contract | `STD:DOC.CONTEXT`, `STD:AUTH.CURRENT_STATE` | Compare enrolled operator intent; missing enrollment is an observation gap. |
| Doctrine quartet (retired) | `STD:DOC.CONTEXT` | Context has roles, not mandatory filenames. Optional missing files are not compliance failures. |

The `doctrine-quartet` ID remains with `retired` maturity and its reason. Its
scanner is retired with the unsupported mandatory-filename assertion. Existing
reports, fingerprints and adjudications remain unchanged and retain their
original engine/source meaning. They are not new findings from this engine.

The former `active-repo-contract-present` P1 repair obligation is replaced by
the distinct `catalog-enrollment-unverified` P3 observation, excluded from repair
tranches. Old adjudications are not silently applied to this different claim.
Enrolled contracts still validate typed commands, Cloudflare posture, release
evidence and artifacts. Validation rejects a catalog edit that retires or drops
an active law: the five scanner laws or `repo-contract`.

Private overlays remain ignored, operator-owned inputs.
`--no-private-contracts` disables the catalog-local overlay; an explicit
`--contracts-overlay` loads only when passed, and the two flags conflict. devctl
has no packaging command; packagers decide what ships. TOML parse errors omit source values. Semantic validation errors and
findings can name a loaded contract's fields, identifiers and file path,
including from an overlay. Audits never edit target repositories, and
`report`/`packet` write only under their required `--out` directory.
