# Cifrarium visual identity

This directory contains the initial, versioned visual identity proposal for
Cifrarium. It is a design artifact for repository use and does not constitute
trademark, domain, or other legal clearance. [Issue #49](https://github.com/teelabs/cifrarium/issues/49)
remains the release gate for qualified review before any public branding claim.

## Assets

- [`cifrarium-logo-sheet.svg`](cifrarium-logo-sheet.svg) — four distinct
  directions, shown in light and dark contexts with horizontal lockups and
  monochrome examples.
- [`cifrarium-mark.svg`](cifrarium-mark.svg) — the recommended compact mark,
  derived from variation A, with no external font or image dependency.

## Direction

The mark treats a rounded `C` as a sealed archive container. The interior
horizontal stroke is a snapshot boundary: it suggests versioned layers without
using a literal lock, shield, or technology symbol. The wordmark is always the
exact lowercase name `cifrarium`.

The four directions are intentionally different:

| Variation | Character | Recommended use |
| --- | --- | --- |
| A — Archive C | Rounded C with a snapshot bar | App icon and default product mark |
| B — Layered C | Offset archival layers | GitHub avatar and dark surfaces |
| C — Folded C | Angular, precise archive fold | CLI icon and monochrome contexts |
| D — Indexed C | Circular index with a catalog point | Favicon and small status surfaces |

Variation A is the default recommendation because its silhouette remains
recognizable at 16×16. Variation B is the strongest avatar alternative;
Variation C is the clearest monochrome treatment; Variation D is reserved for
small circular contexts where the index point remains visible.

## Usage rules

- Use the standalone mark at 16×16 or larger, preserving its square viewBox.
- Use the horizontal lockup when the available width is at least 180 px.
- Keep the provided clear space around the mark at least one quarter of its
  viewBox width.
- Use the supplied dark or light treatment; do not add gradients, shadows,
  textures, or a literal lock/shield motif.
- For monochrome output, use the black or white version without changing the
  geometry or wordmark spacing.
- The cyan accent is `#58D6CF` on dark surfaces; use the dark teal accent
  `#0B7E7A` on light surfaces. The dark base is `#0B1220`, and the light surface
  is `#F4F7FB`. These pairings are intended to preserve strong contrast, but
  each final product surface must still be checked with its actual surrounding
  UI.

## Accessibility and clearance

The wordmark is supplied as text in the sheet for easy review, using a
system-font stack. Product packaging may convert it to outlines only after a
font and licensing decision. Do not present this proposal as an approved
trademark, registered mark, or cleared domain identity until [issue #49](https://github.com/teelabs/cifrarium/issues/49) is
closed by the responsible human reviewers.
