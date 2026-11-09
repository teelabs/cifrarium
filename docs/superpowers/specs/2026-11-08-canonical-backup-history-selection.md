# Canonical backup history selection

## Context

The private Git provider stores encrypted snapshot objects and signed catalog
manifests. Two clients can independently create valid descendants of the same
snapshot. The resulting Git tree contains both lineages, and restore correctly
fails closed because it cannot infer which tip the operator intended.

## Contract

- Inspect and fully verify each remote lineage, including catalog signatures,
  snapshot hashes, encryption, and shared ancestors.
- `cifrarium restore history` is interactive and requires the existing trusted
  local vault/keyring. It only offers branches containing the local vault head.
- After explicit confirmation, write one encrypted and signed marker at
  `history/selection.json`. The marker reveals neither the chosen snapshot ID
  nor the signing key and changes no snapshot/catalog objects.
- Refuse an invalid marker. Restore accepts a fork only when the authenticated
  marker names a verified branch tip.
- Snapshot uploads after selection atomically publish ciphertext, signed
  catalog, and the advanced marker. The upload must extend the selected tip and
  must use the remote commit inspected by the operation; concurrent changes
  cause the push to fail.
- No branch is deleted, rewritten, or pruned. The MCP interface remains
  read-only. The restore service remains in its current state.

## Operational boundary

The marker resolves an existing fork but does not prove that the Git provider
has not been rolled back to an older valid commit. Recovery from a fresh
computer still requires the two shares and an authenticated marker already
present on the provider. If the local vault cannot verify or no remote branch
contains its head, reconcile from a trusted machine whose vault is on the
shared ancestor; never select an unrelated branch by ID alone.

The marker write is a single fast-forward Git commit. It preserves every
provider tree entry. The operation records the inspected remote commit and
aborts if the remote has changed before push. Normal snapshot upload advances
the marker in the same commit as its object and catalog.
