# Configured Vault Root and Contextual Setup

Status: implementation baseline for issue #82.

## Intent

Cifrarium has one configured vault root per operating-system user. The root is
non-secret identity metadata, not a free-form preference supplied independently
to every command. This prevents an accidental command from opening another
vault with the same keyring.

## Contract

The configuration lives at `${XDG_CONFIG_HOME:-$HOME/.config}/cifrarium/config.json`
with schema `1`, canonical root, directory mode `0700`, and file mode `0600`.
Existing components of the root may not be symlinks. Normal commands resolve the
configured root before loading or creating keyring material. An explicit `-root`
is accepted only when it canonicalizes to the configured root; a different root
is a security failure. A new machine establishes the root only through setup.

The keyring payload stores the same canonical root binding. A missing binding is
legacy state: setup may explicitly adopt it, while normal commands stop and
explain the required setup action. Recovery writes the root binding alongside
the recovered key material.

`doctor` remains read-only and can report an unconfigured computer so setup can
explain the next action. `--non-interactive` never establishes configuration,
creates a provider, uploads, captures, displays recovery shares, or enables the
daemon. The systemd unit passes no root; the daemon uses the same resolver.

## Non-goals

This change does not add multi-user vault selection, a casual alternate-root
override, or automatic daemon activation. The later v0.9.0 provider wizard may
create a private remote only after an explicit operator confirmation; it never
uploads a snapshot automatically.

## Verification

Tests cover unconfigured status, setup and reuse, explicit mismatch, symlinked
roots, config permissions, keyring binding, legacy adoption, recovery binding,
and non-interactive no-mutation behavior. Documentation uses root-free normal
commands and reserves `setup --root PATH` for initial configuration or recovery.
