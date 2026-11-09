# Implementation plan: canonical backup history selection

1. Verify every signed remote branch and expose deterministic branch
   inspection without selecting one implicitly.
2. Add an encrypted Ed25519-authenticated canonical-tip marker and validate
   that it points to a fully verified branch.
3. Stage/read the marker from the private Git provider and write it only as an
   explicit fast-forward commit based on the inspected remote revision.
4. Add the interactive `cifrarium restore history` recovery path, anchored to
   the current local vault head and guarded by final terminal confirmation.
5. Make future snapshot uploads update ciphertext, catalog, and marker
   atomically while requiring the new manifest to extend the selected tip.
6. Test fork inspection, marker tampering, provider tree safety, stale remote
   revisions, restore selection, and marker advancement. Run repository local
   verification and complete adversarial review before considering integration.

The change is a MINOR feature; version `0.14.0` contains this release. The
changelog entry moved out of `[Unreleased]` as part of the authorized release.
