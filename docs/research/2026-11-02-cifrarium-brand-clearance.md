# Cifrarium brand and namespace preflight

Status: preliminary technical preflight only; not legal trademark clearance.

Checked: 2026-11-02, UTC.

## Observations

| Surface | Source | Observation | Interpretation |
| --- | --- | --- | --- |
| `cifrarium.com` | [Verisign RDAP](https://rdap.verisign.com/com/v1/domain/cifrarium.com) | RDAP returned the registered domain `CIFRARIUM.COM`, with registration on 2026-09-15 and expiration on 2027-09-15. | The `.com` name is not available for Cifrarium without contacting its registrant or a broker. |
| `cifrarium.dev` | [Google Registry RDAP](https://rdap.org/domain/cifrarium.dev) | The service returned HTTP 404 with `cifrarium.dev not found`. | No RDAP object was observed at query time; registrar availability and reservation status still require a registrar check. |
| `cifrarium.org` | [PIR RDAP](https://rdap.publicinterestregistry.org/rdap/domain/cifrarium.org) | The service returned HTTP 404 with `Object not found`. | No RDAP object was observed at query time; this is not a purchase or legal-clearance result. |
| `cifrarium.net` | [Verisign `.net` RDAP](https://rdap.verisign.com/net/v1/domain/cifrarium.net) | The endpoint returned no domain object in this check. | Treat as unconfirmed until a registrar confirms availability. |
| GitHub namespace | [GitHub organization API](https://api.github.com/orgs/cifrarium), [GitHub repository search](https://github.com/search?q=cifrarium&type=repositories) | The unauthenticated organization endpoint returned 404. Authenticated search in the Teelabs account observed only the private repository `teelabs/cifrarium`. | No public `cifrarium` organization was observed from these checks; organization creation/name reservation remains an operator action. |
| npm package | [npm registry](https://registry.npmjs.org/cifrarium) | Registry returned HTTP 404 `Not found`. | No public package named `cifrarium` was observed; this does not reserve the name. |
| Go package | [pkg.go.dev](https://pkg.go.dev/github.com/teelabs/cifrarium) | The package page returned HTTP 404. | No indexed public Go module was observed for this path. |

## Decision and release gate

The only directly conflicting namespace found is `cifrarium.com`, which is already registered. The repository may use the Cifrarium name internally and in the private GitHub repository, but no public release, domain purchase, package publication, or organization reservation should be inferred from these observations.

Before a public release, an owner must:

1. Select and registrar-verify an available domain or document an alternative namespace.
2. Reserve the intended GitHub organization and package names.
3. Search official trademark databases in the target jurisdictions and obtain qualified legal review for the proposed software mark and logo.
4. Re-run availability checks immediately before reservation because registry state changes.

These checks are evidence for engineering planning only. They do not establish ownership, non-infringement, or trademark clearance.
