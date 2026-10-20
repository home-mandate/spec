<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Certificate authorities for relays (informative)

This list helps gateways and relay operators choose a certificate authority (CA) for the server
certificates of public names (RELAY-v0 Section 6.6). It is informative: conformance does not
depend on it, and a CA that is not listed but meets both conditions below may be used just as
well.

A CA is listed when, as far as public sources show,

1. it submits **every** certificate it issues to Certificate Transparency logs, so that a
   gateway's monitoring sees it (RELAY-v0 Section 6.7); and
2. it **enforces** the CAA parameters `accounturi` and `validationmethods` of RFC 8657, so that
   only the gateway's ACME account can obtain a certificate, and only through DNS (RELAY-v0
   Sections 5.6, 6.3, 6.4).

| CA | `caa_identity` | Logs every certificate | Enforces `accounturi`, `validationmethods` | Checked |
|---|---|---|---|---|
| Let's Encrypt | `letsencrypt.org` | "Let's Encrypt submits all certificates we issue to CT logs." ([CT logs](https://letsencrypt.org/docs/ct-logs/)) | documented in [CAA](https://letsencrypt.org/docs/caa/); checked at every issuance by Boulder ([`va/caa.go`](https://github.com/letsencrypt/boulder/blob/main/va/caa.go)) | 2026-10-20 |

To propose a CA, open an issue with public sources for both conditions. A CA is removed when a
source shows that it no longer meets one of them; operators then remove it from `acme_cas`, and
gateways move to another listed CA as RELAY-v0 Section 6.6 describes.
