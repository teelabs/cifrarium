# Provider Wizard and Symlink Recovery Documentation Plan

**Spec:** `docs/superpowers/specs/2026-11-04-provider-wizard-cli-design.md`

## Goal

Keep the operational documentation, implementation contract, and PO/SM
acceptance evidence aligned for the released v0.9.0 provider wizard and for
safe recovery from rejected symlinked configuration files.

## Tasks

1. Add one consistent symlink correction procedure to the README, user guide,
   and agent contract.
2. Record the canonical subcommand, provider wizard, share, daemon, and
   symlink contracts in the dedicated v0.9.0 specification.
3. Remove obsolete root-plan claims that contradict the shipped provider
   wizard, especially the claim that the wizard never persists recovery shares.
4. Add an Unreleased documentation/governance note without changing the
   released version; a future code or product change must receive its own
   SemVer classification.

## Governance gap

Issue #82 covered the configured-root feature and was closed with v0.8.0
evidence. The v0.9.0 CLI/provider scope requires a separate PO/SM tracker
entry or an explicit update to the active roadmap item. The repository must
not treat the closed issue or stale board state as current acceptance evidence.

## Verification

Run `git diff --check`, `./scripts/verify-version-changelog.sh`,
`./scripts/verify-secrets.sh`, and search for contradictory legacy command or
share-persistence instructions before integration.
