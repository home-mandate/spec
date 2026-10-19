<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Home-Mandate Relay Specification v0 (Draft)

Status: **Skeleton of a working draft. Not part of `v0.1.0` of the Home-Mandate
Specification**; the freeze of Section 14 of SPEC-v0 does not cover this document, its schema
or its examples. Sections marked *To be specified* hold the agreed outline only.
License of this document: CC BY 4.0 (`LICENSE-docs`). Schema and examples: Apache 2.0
(`LICENSE`).

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT" and "MAY" in this document are to be
interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in
all capitals.

## 1. Goal

A gateway in a home is usually behind NAT and cannot be reached by cloud agents. A **relay**
makes it reachable under a public name: the gateway connects outbound to the relay, and the
relay passes the agents' TLS connections through to the gateway without terminating them.

Relays MAY be run by anyone. This document defines what a gateway and a relay operator need
to work together without knowing each other in advance, and what an operator MUST do so that
a household can trust a relay it does not control:

| Part | Contents |
|---|---|
| Tunnel protocol (Section 4) | how the gateway and the relay connect and how agent connections are passed through |
| Pairing and issuance (Section 5) | how a gateway is paired with an operator, obtains and renews its certificates, and is unpaired |
| Names and certificates (Section 6) | public names, protection levels, Certificate Transparency monitoring, pinning of the relay |
| Operator obligations (Section 7) | what a conforming operator MUST do and MUST NOT do |

The specification builds on existing standards:

| Purpose | Standard |
|---|---|
| Transport | TLS 1.3 (RFC 8446) |
| Identity of the gateway towards the relay | SPIFFE X.509-SVID |
| Requests of the gateway to the operator | JSON Web Signature (RFC 7515), patterns of ACME (RFC 8555) |
| Certificate requests | PKCS #10 (RFC 2986) |
| Public certificate of the home | ACME (RFC 8555) with the `dns-01` challenge, CAA (RFC 8659, RFC 8657), Certificate Transparency (RFC 6962 and the logs that browsers accept, whatever interface they offer) |
| Errors | Problem Details (RFC 9457) |

### 1.1 What a relay can and cannot do (informative)

The TLS connection of an agent ends in the gateway, with a key that never leaves the home.
The relay sees the server name, the agent's address, the time and the number of bytes, not
the content. OAuth, the evaluation of mandates and approvals take place in the home
(SPEC-v0).

The remaining risk is the operator's control over the DNS of the public name: whoever
controls it can obtain a second certificate for the name and open the TLS connection at the
relay. This specification therefore defines two protection levels (Section 6), both
mandatory for every operator:

- **Standard** (`<id>.<name-domain>`): the operator cannot read **unnoticed**. Every
  certificate for the name appears in Certificate Transparency logs, and the gateway MUST
  watch them and raise an alarm.
- **Own domain** (a name of the household): the operator **cannot** obtain a certificate
  for the name, because a CAA record of the household binds issuance to the gateway's own
  ACME account.

### 1.2 Overview (informative)

```mermaid
sequenceDiagram
  participant U as Household (admin)
  participant P as Operator portal
  participant G as Gateway
  participant O as Operator (enrollment, CA, DNS)
  participant R as Relay
  participant A as Agent
  U->>P: create pairing code
  U->>G: enter pairing string (operator domain + code)
  G->>O: fetch metadata (Section 3)
  G->>U: show operator, protection levels, max_offline_days; confirm
  G->>O: pair: installation key, CSR, code binding (Section 5)
  O-->>G: home ID, public name, tunnel certificate
  G->>O: set ACME challenge for its name
  Note over G: obtains its server certificate itself
  G->>R: tunnel with the tunnel certificate (Section 4)
  A->>R: TLS to https://<id>.<name-domain>/mcp
  R->>G: byte stream through the tunnel, TLS ends in the gateway
```

## 2. Terminology

- **Gateway:** the implementation in the home (SPEC-v0) that serves agents and connects to the
  relay.
- **Operator:** whoever runs a relay together with its portal, enrollment endpoint, CA and
  DNS zones.
- **Relay:** the server of the operator that accepts tunnel connections of gateways and
  agent connections, and passes the latter through.
- **Portal:** the operator's user interface where a household creates pairing codes, sees and
  unpairs its installations.
- **Operator domain:** the DNS domain under which the operator publishes its metadata
  (Section 3).
- **Name domain:** the DNS domain under which homes get their public names at the protection
  level Standard. It is not the operator domain and serves nothing but homes (Section 7).
- **Trust domain:** the SPIFFE trust domain of the operator's tunnel certificates.
- **Home ID** (`<id>`): the identifier the operator assigns to a paired gateway: 26 characters
  of lower-case base32 `[a-z2-7]` (130 random bits).
- **Public name:** the DNS name under which agents reach the gateway; `<id>.<name-domain>` or a
  name in the household's own domain.
- **Installation key:** a long-lived key pair generated by the gateway at pairing; it signs the
  gateway's requests to the operator.
- **Tunnel certificate:** the short-lived X.509-SVID with which the gateway authenticates to
  the relay.
- **Server certificate:** the publicly trusted certificate of the public name; it is presented
  to agents and obtained by the gateway itself through ACME.
- **ACME account key:** the gateway's own key for its account at the public CA.
- **Pairing code:** a single-use secret that the portal shows and the household enters into
  the gateway.
- **Pairing string:** the operator domain and the pairing code in one string, for typing or as
  a QR code.
- **Protection level:** Standard or Own domain (Sections 1.1 and 6).

## 3. Operator metadata

An operator publishes its parameters as a JSON document at

```
https://<operator-domain>/.well-known/home-mandate-relay
```

The document MUST validate against `relay/schema/metadata-v0.schema.json`; an example is
`relay/examples/metadata.json`. A gateway MUST fetch it over HTTPS with a certificate that is
valid for the operator domain under the gateway's ordinary trust store, MUST NOT follow
redirects, and MUST reject a document larger than 16 KiB. The document is closed: a member that
the schema does not list makes it invalid. New members come with a new `type`; until this
specification is released, the schema can still change under the same `type`.

| Member | Meaning |
|---|---|
| `type` | `https://home-mandate.org/relay-metadata/v0` |
| `operator_domain` | MUST equal the host from which the document was fetched |
| `name_domain` | domain of the public names at the protection level Standard; MUST NOT be the operator domain |
| `trust_domain` | SPIFFE trust domain of the tunnel certificates |
| `enrollment` | HTTPS URL of the enrollment directory (Section 5); its host MUST be the operator domain or a subdomain of it |
| `relay` | `host` and `port` of the relay |
| `relay_pins` | SHA-256 digests (base64url) of the SubjectPublicKeyInfo the gateway pins for the relay; at least two (Section 6) |
| `max_offline_days` | how long after the expiry of its last tunnel certificate a gateway can still obtain a new one with its installation key; 7 to 90, RECOMMENDED 30 (Section 5.4) |
| `protection_levels` | MUST list `standard` and `own-domain` (Section 7) |
| `portal` | HTTPS URL of the portal, shown to the household |
| `privacy_policy` | HTTPS URL of the operator's privacy policy, shown to the household |

Before it completes a pairing, the gateway MUST show the household the operator domain, the
protection levels and `max_offline_days`. A change of the document applies to an existing
pairing from its next renewal on (Section 5.4); the gateway MUST tell the household when
`max_offline_days` or `protection_levels` changed. Changes of `relay_pins` follow Section 6.

## 4. Tunnel protocol

*To be specified.* The starting point is the Home-Mandate tunnel protocol v1
(`docs/tunnel-protocol-v1.md` in `github.com/home-mandate/relay`): one control connection and
one mutually authenticated connection per agent connection. This section will take it over with
the name domain and the trust domain as parameters of the operator (Section 3) and the tunnel
certificate of Section 5.3; the CA that issues tunnel certificates belongs to the operator and
is not published. Until this section is specified, no interoperability between independent
gateways and operators is claimed.

## 5. Pairing and issuance

*To be specified.* Agreed outline:

### 5.1 Requests

The gateway's requests are JSON objects signed as JWS (RFC 7515) in the flattened JSON
serialization. An operator MUST accept EdDSA (Ed25519, RFC 8037) and ES256; a gateway uses one
of them. As in ACME (RFC 8555 Section 6): every request carries a fresh nonce from
the operator and the URL it is sent to, both in the protected header and both checked; the
pairing request carries the public installation key as `jwk`, every later request references
the installation by `kid`; reads are signed POST requests with an empty payload. Errors are
Problem Details (RFC 9457) with types under `https://home-mandate.org/relay/errors/`.

### 5.2 Pairing

- Only a local administrator of the gateway can start a pairing, by entering a pairing string;
  the gateway shows what Section 3 requires and asks for confirmation.
- A pairing code is single-use, valid for at most 10 minutes, bound to the account that
  created it and rate limited. Wrong, expired and used codes are answered alike.
- The gateway generates four separate key pairs, none of which leaves the home: installation
  key, tunnel key, ACME account key, server key.
- The pairing request binds the code to the installation key (as External Account Binding,
  RFC 8555 Section 7.3.4) and carries a PKCS #10 request for the tunnel certificate.
- The operator answers with the home ID, the public name and the first tunnel certificate.
- A gateway is paired with at most one operator at a time. Pairing with another operator
  gives a new public name and therefore a new OAuth issuer.
- Open: re-pairing an existing installation from the portal while keeping its home ID.

### 5.3 Tunnel certificate

Issued by the operator's CA for at most 24 hours. The CA alone determines the contents and
ignores names requested in the CSR: exactly one URI SAN
`spiffe://<trust-domain>/home/<id>/gateway`, `cA=false`, key usage `digitalSignature` only
(critical), extended key usage `serverAuth` and `clientAuth` (as X.509-SVID recommends), a random
serial number, no personal data. The CA carries a URI name constraint for its trust domain.

### 5.4 Renewal and re-issuance

The gateway renews its tunnel certificate before it expires, with a new tunnel key. After an
expiry, the installation key alone authenticates a re-issuance for `max_offline_days`
(Section 3); after that, only a new pairing helps. A gateway MAY apply a shorter limit of its
own; it then deletes its installation key. A lower `max_offline_days` applies to an
installation from its next successful renewal on. The installation key can be replaced by a
key change signed with the old and the new key (RFC 8555 Section 7.3.5).

### 5.5 ACME support

The gateway runs ACME itself, with its own account, and renews using ACME Renewal Information
(RFC 9773). For the protection level Standard the operator sets the `_acme-challenge` TXT
record of exactly the requesting gateway's public name and nothing else. The gateway tells the
operator its ACME account URI (Section 6).

### 5.6 Unpairing, blocking, pausing

Unpairing from the portal or from the gateway: the operator stops renewals, blocks the
installation key, denies the serial numbers, closes open connections and removes the DNS
records of the name; the gateway deletes its keys, revokes its server certificate and
deactivates its ACME account. A renewal after unpairing gets a distinct error, so that the
gateway can show the state.

### 5.7 Limits of the operator

No message of this specification carries mandates, approver keys or issuer keys. In responses
of the enrollment endpoint a gateway MUST ignore any member it does not know. An operator cannot change what a household allows.

## 6. Names and certificates

*To be specified:* public names at both protection levels; CAA with `accounturi` and
`validationmethods=dns-01` (RFC 8657) and when a name counts as Own domain; the gateway itself
determines the protection level and checks it regularly, never the relay; delegation of
`_acme-challenge` by CNAME and why it gives issuance power to the target; Certificate
Transparency monitoring in the gateway with an alarm; what Own domain cannot protect against
(a household that delegates its DNS, a CA that ignores RFC 8657); pinning of the relay and rotation of the
pins; changing the public name.

## 7. Operator obligations

*To be specified:* name domain separate from the portal and the operator domain, so that a
gateway cannot set cookies for the portal (until the name domain is on the Public Suffix List,
gateways use only `__Host-` cookies); CAA for the
name domain; Certificate Transparency monitoring; both protection levels; minimal metadata and
their retention; denylists; rate limits of the public CA and the Public Suffix List;
conformance tests.

## 8. Conformance

*To be specified.* Every normative rule gets a machine-readable case; the schema of the
metadata document is `relay/schema/metadata-v0.schema.json`.

## 9. Security considerations

*To be specified*, as a table of attackers as in SPEC-v0 Section 12.2: an operator that wants
to read, a household paired with a malicious operator, a stolen installation key, a stolen
tunnel key, a guessed or intercepted pairing code, a compromised operator CA.

## 10. Privacy considerations

*To be specified:* what an operator learns (home ID, server name, agent address, time, byte
counts) and how long it may keep it.

## Changelog

### Unreleased

- Skeleton: goal, terminology, operator metadata with schema and example, outline of pairing
  and issuance.
