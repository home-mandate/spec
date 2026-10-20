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
| Transport of the tunnel | TLS 1.3 (RFC 8446) |
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
  G->>U: show operator, protection levels, max_offline_days, ask to confirm
  G->>O: pair: installation key, CSR, code binding (Section 5)
  O-->>G: home ID, public name, tunnel certificate
  G->>O: report its ACME account (CAA)
  G->>O: set ACME challenge for its name
  Note over G: obtains its server certificate itself
  G->>R: tunnel with the tunnel certificate (Section 4)
  A->>R: TLS to https://#lt;id#gt;.#lt;name-domain#gt;/mcp
  R->>G: byte stream through the tunnel, TLS ends in the gateway
```

## 2. Terminology

- **Gateway:** the implementation in the home (SPEC-v0) that serves agents and connects to the
  relay.
- **Operator:** whoever runs a relay together with its portal, enrollment endpoint, CA and
  DNS zones.
- **Relay:** the server of the operator that accepts tunnel connections of gateways and
  agent connections, and passes the latter through.
- **Enrollment endpoint:** the operator's HTTPS interface for the requests of the gateway
  (Section 5).
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
| `enrollment` | HTTPS URL of the enrollment directory (Section 5.1); its host MUST be the operator domain or a subdomain of it |
| `relay` | `host` and `port` of the relay |
| `relay_pins` | SHA-256 digests (base64url) of the SubjectPublicKeyInfo the gateway pins for the relay; at least two (Section 6) |
| `max_offline_days` | how long an installation can be without a valid tunnel certificate before only a new pairing helps; 7 to 90, RECOMMENDED 30 (Section 5.5) |
| `protection_levels` | MUST list `standard` and `own-domain` (Section 7) |
| `portal` | HTTPS URL of the portal, shown to the household |
| `privacy_policy` | HTTPS URL of the operator's privacy policy, shown to the household |

Before it completes a pairing, the gateway MUST show the household the operator domain, the
protection levels and `max_offline_days`. A change of the document applies to an existing
pairing from its next renewal on (Section 5.5); the gateway MUST tell the household when
`max_offline_days` or `protection_levels` changed. Changes of `relay_pins` follow Section 6.

## 4. Tunnel protocol

*To be specified.* The starting point is the Home-Mandate tunnel protocol v1
(`docs/tunnel-protocol-v1.md` in `github.com/home-mandate/relay`): one control connection and
one mutually authenticated connection per agent connection. This section will take it over with
the name domain and the trust domain as parameters of the operator (Section 3) and the tunnel
certificate of Section 5.4; the CA that issues tunnel certificates belongs to the operator and
is not published. Until this section is specified, no interoperability between independent
gateways and operators is claimed.

## 5. Pairing and issuance

The gateway talks to the operator's **enrollment endpoint** over HTTPS (TLS 1.2 or later with a
certificate valid for its host under the gateway's ordinary trust store). All messages are
described by `relay/schema/enrollment-v0.schema.json`; examples are in `relay/examples/`.
Section 1.2 shows the flow.

### 5.1 Directory, nonces and requests

**Directory.** `GET` on the URL `enrollment` of the metadata (Section 3) returns `200` with a
JSON object holding the URLs `new_nonce`, `pair` and `key_change` (`$defs/directory`). Every URL
to which the gateway sends requests (those of the directory, the installation URL and the URLs
in the installation) MUST be an HTTPS URL on the host of `enrollment`; a gateway MUST NOT send a
request to any other host.

**Nonces.** Every response of the enrollment endpoint, including errors, carries a fresh nonce
in the header `Replay-Nonce`: base64url without padding, at least 128 random bits. `HEAD` on
`new_nonce` returns `200`, `GET` returns `204`, both without a body. The operator accepts every
nonce once, MAY let unused nonces expire, and answers an unknown, used or expired nonce with the
error `bad-nonce` and a fresh nonce; the gateway then repeats the request once with it, and
after a second `bad-nonce` retries later with backoff.

**Requests.** Every request except to the directory and to `new_nonce` is a `POST` with the
content type `application/jose` whose body is a JWS (RFC 7515) in compact serialization:

- The protected header (`$defs/protected_header`) has exactly `alg`, `nonce`, `url` and one of
  `jwk` and `kid`. `alg` is `EdDSA` (Ed25519, RFC 8037) or `ES256`, matching the key; an
  operator MUST accept both. `url` MUST equal the URL the request was sent to, byte for byte.
  `jwk` is the public installation key and appears only in a pairing request (Section 5.2);
  every other request carries `kid`, the installation URL (Section 5.3). Any other header
  member, and a `jwk` with a private part, make the request invalid.
- The spelling rules of SPEC-v0 Section 7.1 apply: base64url without padding, case-sensitive
  member names, and for ES256 only the lower `s`.
- The payload is a JSON object of the type the URL expects, or empty for a read ("POST-as-GET",
  RFC 8555 Section 6.3). Request objects are closed: an operator MUST reject a request with a
  member the schema does not list.

The operator processes a request in this order; a request that fails a step has no effect:

1. the header against `$defs/protected_header` (`malformed`);
2. with `jwk`, the URL MUST be `pair`; with `kid`, it MUST NOT be `pair` (`malformed`);
3. with `kid`: the installation it names (none: `bad-signature`; unpaired or replaced:
   `unpaired`), and the URL MUST be `key_change`, the installation URL of that installation or
   a URL in it (`malformed`); one installation can never act on another;
4. the signature with that key (`bad-signature`); from here on the nonce is used up, whatever
   happens next; then the nonce (`bad-nonce`) and `url` (`malformed`);
5. the state of the installation (Sections 5.5 and 5.7);
6. the payload (`malformed`, or the error of the operation).

An installation URL MUST contain at least 128 random bits, so that whether an installation
exists cannot be learnt by guessing (step 3 answers before the signature is checked).

**Responses and errors.** Successful responses are JSON (`application/json`) with the status
the operation names. Errors are Problem Details (RFC 9457, `application/problem+json`) whose
`type` is `https://home-mandate.org/relay/errors/` followed by one of the names in the table. A
gateway treats any other error response as `server-internal`, and ignores members it does not
know in every response.

| Error | Status | Meaning | Gateway |
|---|---|---|---|
| `malformed` | 400 | the request does not match this section or the schema | reports a defect, does not repeat the request |
| `bad-nonce` | 400 | nonce unknown, used or expired | repeats once with the fresh nonce |
| `bad-signature` | 401 | a signature does not verify, or `kid` names no installation | stops using the operator and tells the household |
| `pairing-refused` | 403 | the pairing code is wrong, expired, used, not yet usable or not for this operator; the operator does not say which | asks for a new code |
| `confirmation-required` | 403 | the change needs the household's confirmation in the portal (Section 5.6) | tells the household and repeats after confirmation |
| `offline-too-long` | 403 | the installation was without a valid tunnel certificate longer than `max_offline_days` (Section 5.5) | ends the pairing locally (Section 5.7) |
| `blocked` | 403 | the operator blocked the installation (Section 5.7) | Section 5.7 |
| `bad-csr` | 400 | the certificate request breaks Section 5.4 | creates a new tunnel key and request |
| `key-conflict` | 409 | the new key of a key change is already in use (Section 5.5) | creates a new key |
| `unpaired` | 410 | the installation was unpaired or replaced (Sections 5.2, 5.7) | ends the pairing locally (Section 5.7) |
| `rate-limited` | 429 | too many requests; the response carries `Retry-After` | waits at least that long |
| `server-internal` | 500 | anything else | retries with exponential backoff |

### 5.2 Pairing

**Pairing code and pairing string.** The portal creates a pairing code for the account of the
household: 16 characters from `A–Z 2–7` (80 random bits), shown in four groups of four separated
by `-`. It is single-use, valid for at most 10 minutes from the moment it can be used, and bound
to that account. The operator MUST limit failed attempts per source address and in total, and
answer every code that cannot be redeemed alike (`pairing-refused`), in the same time. The
portal shows the **pairing string** `<operator-domain>/<code>`, with the operator domain in lower
case, as text and as a QR code, for example `relay-operator.example/ABCD-EFGH-IJKL-MNOP`
(`$defs/pairing_string`). A gateway accepts the code in either case and with or without the
hyphens, and sends it in upper case without them.

**At the gateway.** Only a local administrator of the gateway can start a pairing, and only
while the gateway is not paired with any operator. The gateway

1. fetches the metadata from the operator domain of the pairing string (Section 3);
2. shows the household the operator domain, the protection levels and `max_offline_days`, and
   asks for confirmation; without it, nothing is sent;
3. generates four separate key pairs, none of which ever leaves the gateway: the installation
   key, the tunnel key, the ACME account key and the server key. The installation key MUST NOT
   be used for anything but the requests of this section;
4. fetches the directory and a nonce, and sends a pairing request to `pair`, signed with the
   installation key and carrying it as `jwk`. The payload (`$defs/pair_request`) holds the code
   and a certificate request for the tunnel key (Section 5.4). Because the code is inside the
   signed payload, it is bound to this installation key; a pairing code that has been used
   cannot be used again with any key. If the response is lost, the gateway repeats the request
   with the same installation key and code (and a fresh nonce); the operator MUST answer a
   pairing request whose code was redeemed by the same installation key, within the code's
   validity, like the first one, with a new tunnel certificate for the repeated request.

**At the operator.** The operator processes the request (Section 5.1), redeems the code, checks
the certificate request, refuses an installation key that another installation already uses
(`key-conflict`), and creates the installation:

- a new **home ID** (Section 2) that it has never assigned before and MUST NOT assign again,
  also not after unpairing;
- the **installation URL**, which is the `kid` of all later requests;
- the public name `<home ID>.<name_domain>`;
- the first tunnel certificate (Section 5.4).

It answers `201 Created` with the installation URL in `Location` and a body
(`$defs/pair_response`) with the installation (Section 5.3) and the tunnel certificate. The
gateway MUST check that the public name is the home ID followed by `.` and the `name_domain`
of the metadata, and that the certificate matches Section 5.4 and its own tunnel key. The
operator MUST notify the household of every new installation and show it in the portal. Right
after pairing, the gateway creates its ACME account and reports it (Section 5.6), and shows the
household the account URI, so that the household can compare it with what the portal shows.

**Pairing again.** A gateway is paired with at most one operator at a time; to change the
operator it is unpaired first (Section 5.7). A new pairing gives a new home ID, a new public
name and therefore a new OAuth issuer; agents must be connected again.

An operator MAY offer, in its portal, a pairing code **for an existing installation**, for a
gateway that lost its keys (reinstallation, restored backup, `offline-too-long`). Pairing with
such a code keeps the home ID and the public name and **replaces** the installation: it gets a
new installation URL, the old installation URL answers `unpaired`, the
operator denies their tunnel certificates and closes their connections, and the reported ACME
account is cleared, so that the new gateway reports its own (Section 5.6). Because whoever
controls the household's account can thereby move the public name to another gateway, the
operator MUST

- require a fresh authentication of the person before it creates such a code;
- notify the household on all its channels when the code is created;
- make the code usable only after a waiting time of at least 24 hours, during which the
  household can cancel it in the portal and through the notification.

### 5.3 Installation

A POST-as-GET on the installation URL returns `200` with the installation
(`$defs/installation`):

| Member | Meaning |
|---|---|
| `status` | `active`; `paused` (the household paused remote access in the portal; the relay passes no agent connections, all requests work); `blocked` (Section 5.7); `unpaired` (only in the answer to unpairing, Section 5.7) |
| `home_id`, `public_name` | as assigned at pairing |
| `max_offline_days` | the value in force for this installation (Section 5.5) |
| `certificate` | URL for tunnel certificates (Section 5.4) |
| `acme_challenge` | URL for the ACME challenge records (Section 5.6) |
| `acme_account`, `caa_identity` | the ACME account the gateway reported (Section 5.6), if any |

A gateway SHOULD read its installation with every renewal, and at most once an hour otherwise,
and show the status to the household.

A `POST` to the installation URL with a payload (`$defs/installation_update`) changes it and is
answered with `200` and the installation: `{"acme_account": …, "caa_identity": …}` reports the
gateway's ACME account (Section 5.6), and `{"status": "unpaired"}` unpairs the installation
(Section 5.7).

### 5.4 Tunnel certificate

A `POST` to `certificate` with a payload `{"csr": …}` (`$defs/certificate_request`) asks for a
tunnel certificate and is answered with `200`; the pairing request carries the same member.
`csr` is a PKCS #10 request (RFC 2986) in DER, base64url without padding. The operator MUST
refuse it with `bad-csr` unless

- its signature verifies with the public key it contains;
- the key is ECDSA P-256 or Ed25519 (an operator MUST accept both);
- the key differs from the installation key and from the key of every tunnel certificate the
  operator issued to this installation before.

Everything else in the request (subject, extensions, requested names) is ignored. The operator's
CA issues a certificate that

- contains exactly one subject alternative name, the URI
  `spiffe://<trust_domain>/home/<home ID>/gateway`, and an empty subject;
- has a `notAfter` at most 24 hours after its `notBefore`, which is no earlier than 5 minutes
  before issuance;
- has `cA=false`, key usage `digitalSignature` only (critical), and extended key usage
  `serverAuth` and `clientAuth`, as X.509-SVID recommends;
- has a serial number with at least 64 random bits;
- contains no other information about the household.

The CA that issues tunnel certificates MUST carry a name constraint (RFC 5280 Section
4.2.1.10) that permits only URIs whose host is `trust_domain`, and MUST NOT issue anything but
tunnel certificates.

The response (`$defs/certificate_response`) holds `chain`, the issued certificate followed by the
certificates of the CA that issued it, each in DER and base64url without padding, and
`not_after`, the expiry of the issued certificate (RFC 3339, UTC, `Z`). The gateway needs none of
the CA certificates to trust the relay (Section 6).

### 5.5 Renewal, re-issuance and key change

A gateway SHOULD ask for a new tunnel certificate when two thirds of the validity of the current
one have passed, always with a new tunnel key, and SHOULD retry with exponential backoff. It
uses the new certificate for new connections and MUST reconnect with it before the old one
expires (tunnel protocol, Section 4).

A request after the current certificate expired is a **re-issuance**. It is authenticated by
the installation key alone. The **offline time** of an installation is the time since the expiry
of its last tunnel certificate; while it is `blocked`, the time does not run. Once the offline
time exceeds `max_offline_days`, the operator MUST answer every request of the installation
except reading it and unpairing it with `offline-too-long`. The value that counts is the one in
force at the last successful issuance; a changed value in the metadata applies from the next
issuance on. A gateway MAY apply a shorter limit of its own; it then behaves as on
`offline-too-long` (Section 5.7).

The operator MUST show the household each issuance (time and source address) in the portal,
MUST notify the household of a re-issuance, and SHOULD limit issuances per installation (for
example to six per day).

**Key change.** A gateway replaces its installation key as in RFC 8555 Section 7.3.5. It sends to
`key_change` a request signed with the old key (`kid`) whose payload is `{"jws": …}`
(`$defs/key_change_request`): a JWS in compact serialization, signed with the new key, whose
protected header has exactly `alg`, `jwk` (the new key) and `url` (the URL of `key_change`)
(`$defs/key_change_header`) and whose payload is `{"installation": …, "old_key": …}`
(`$defs/key_change`). The operator checks the inner signature (`bad-signature`), that `url`
matches and `installation` is the `kid` of the outer request and `old_key` its key
(`malformed`), and that the new key is neither the key of another installation nor the key of
one of this installation's tunnel certificates (`key-conflict`). It then replaces the key,
answers `200` with the installation, and MUST notify the household. The gateway keeps the old key
until a request signed with the new key succeeded; if it does not know whether a key change took
effect (the response was lost), it reads its installation with the new key, and on
`bad-signature` with the old one.

### 5.6 ACME support

The gateway obtains its server certificate itself, with ACME (RFC 8555), its own account and
the `dns-01` challenge, and renews it using ACME Renewal Information (RFC 9773). The operator
never sees the server key or the ACME account key.

**Account.** The gateway reports its ACME account (`$defs/installation_update`): `acme_account`,
the account URI at the CA, and `caa_identity`, the issuer domain name that CA uses in CAA records
(RFC 8659 Section 4.2). The operator MUST publish for the public name a CAA record that allows
only this account to obtain certificates (`issue` with the parameters `accounturi` and
`validationmethods=dns-01`, RFC 8657); Section 6 gives the details. The first report after
pairing (or after a replacement, Section 5.2) takes effect at once and is answered with `200`
once the CAA record is served by all authoritative name servers, within 120 seconds. Every later
change MUST be confirmed by the household:

- the operator answers `confirmation-required`, keeps the reported account in force, stores the
  reported pair as pending (a later report replaces it), and notifies the household;
- the portal shows the pending `acme_account` and `caa_identity`, which the household compares
  with the account URI its gateway shows (Section 5.2), and the confirmation applies to exactly
  that pair;
- after the confirmation the operator puts the pair in force and publishes its CAA record; the
  gateway sees the change when it reads its installation, which it does at most every few
  minutes while a change is pending.

**Challenge.** A `POST` to `acme_challenge` with `{"values": […]}`
(`$defs/acme_challenge_request`) makes the operator publish exactly these values as TXT records
at `_acme-challenge.<public name>`, replacing earlier ones; an empty list removes them. A value
is the key authorization digest of RFC 8555 Section 8.4 (43 characters, base64url); at most two
values are allowed. The operator refuses the request with `malformed` while no ACME account is
reported. It answers `200` with the same object once the records are served by all its
authoritative name servers, within 120 seconds, or else `server-internal`; the gateway SHOULD
check the records itself before it asks the CA to validate. The operator MUST NOT publish TXT
records for any other name on behalf of an installation, and SHOULD remove records after one
hour.

### 5.7 Unpairing, blocking and the gateway's state

**Unpairing** ends an installation for good. It starts in the portal (the household, or the
deletion of its account) or in the gateway: a `{"status": "unpaired"}` update (Section 5.3),
answered with `200` and the installation with the status `unpaired`. The operator then

- answers every further request of the installation with `unpaired`;
- adds the serial numbers of all unexpired tunnel certificates of the installation to the
  relay's denylist and closes their connections (tunnel protocol, Section 4);
- removes every DNS record of the public name, including challenge and CAA records;
- keeps the home ID reserved (Section 5.2).

**Ending the pairing locally.** A gateway that unpairs or receives `unpaired` MUST close the
tunnel, delete its installation key and tunnel key, revoke its server certificate and deactivate
its ACME account (RFC 8555 Sections 7.6 and 7.3.6), and show the household that remote access
through this operator has ended. A gateway that receives `offline-too-long`, or whose own limit
passed (Section 5.5), MUST close the tunnel and delete its installation key and tunnel key, but
MUST NOT send the unpairing request: the household decides in the portal whether to unpair the
installation or to pair the gateway again with a code for the existing installation, which keeps
the public name (Section 5.2). Either way, the gateway is then no longer paired.

**Blocking** is an operator measure against abuse. A blocked installation can read its
installation and unpair; every other request is answered with `blocked`, its tunnel certificates
are denied and their connections closed. Lifting the block returns the installation to its
previous state. A gateway that receives `blocked` keeps its keys, closes the tunnel, shows the
household the state and the portal, and reads its installation at most once an hour to learn
when the block is lifted.

**Without the operator.** A gateway MUST let its local administrator turn remote access off at
any time without contacting the operator: it then closes the tunnel and stops renewing; its keys
are kept until the household unpairs. The offline time (Section 5.5) runs meanwhile.

**Limits of the operator.** No message of this section carries mandates, approver keys or issuer
keys, and a gateway MUST NOT accept any from an operator. An operator cannot change what a
household allows; it can only stop being the way in.

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

The rows below cover pairing and issuance (Section 5); the tunnel (Section 4) and names and
certificates (Section 6) add theirs when they are specified. Throughout, two facts limit what an
attacker on the relay side gains. An agent verifies the **server certificate** of the public
name, whose key exists only in the gateway. And a public CA that follows RFC 8657 issues a
certificate for the name only to the ACME account in its CAA record, which is the gateway's own
account (Section 5.6). Whoever controls a tunnel without the server key receives agents'
connections but cannot complete their TLS handshakes. Both facts assume an operator that follows
this specification; what an operator itself could do is the subject of Section 6.

| Attacker | What the specification does | What remains |
|---|---|---|
| **Guesses a pairing code** | 80 random bits, at most 10 minutes, single use, limited attempts per address and in total, one answer for all failures (Section 5.2) | – |
| **Intercepts or is shown a pairing code** for a new installation before the household uses it | The code is bound to the household's account, not to a gateway; the operator notifies the household of every new installation (Section 5.2) | The attacker's gateway is paired to the household's account until the household notices and unpairs it. It gets a new public name and does not receive the household's agents |
| **Intercepts or is shown a pairing code for an existing installation** | Created only after a fresh authentication, announced on all channels, usable only after at least 24 hours in which the household can cancel it (Section 5.2) | A household that ignores the announcement loses its public name to the attacker's gateway, which then receives the household's agents and can complete their TLS. The replaced gateway learns it (`unpaired`) and tells the household; the new server certificate appears in Certificate Transparency (Section 6) |
| **Lures a household to a malicious operator** (a pairing string of the attacker) | Pairing only by the local administrator, after the gateway showed the operator domain and its parameters (Section 5.2) | A household that confirms anyway uses that operator, with the protection Section 6 gives against operators |
| **Replays a request** | Single-use nonces and the signed `url` (Section 5.1) | – |
| **Another installation's key** (any paired gateway, also one paired to the attacker's own account) | The URL of a request must belong to the installation of its key (Section 5.1); installation URLs carry 128 random bits | – |
| **Steals the installation key** | Tunnel certificates and ACME challenge records, but no server certificate: the CAA record binds issuance to the gateway's ACME account, and changing the account needs the household's confirmation (Section 5.6). Every issuance is shown in the portal, re-issuances and key changes are notified; a key that nobody uses for `max_offline_days` is useless; unpairing ends it (Sections 5.5, 5.7) | Until the household unpairs, the attacker can take the tunnel over and deny service, learn when agents connect, lock the gateway out with a key change, and unpair the installation, which loses the public name for good. A CA that ignores RFC 8657 would issue to the attacker; Section 6 limits the CAs |
| **Steals the installation key and the ACME account key** (a compromised gateway) | – | Everything the gateway can do, until the household unpairs |
| **Steals a tunnel key** | Tunnel certificates live at most 24 hours; a new key at every renewal; denylist (Sections 5.4, 5.7) | Taking the tunnel over for at most the rest of that certificate's life |
| **Takes over the household's account at the operator** | Unpairing and pairing codes stay with the account; codes for an existing installation and changes of the ACME account need a fresh authentication or the household's confirmation and are announced (Sections 5.2, 5.6) | The attacker can end remote access, and can move the public name as in the row above, announced and with a waiting time |
| **Compromises the operator's tunnel CA** | Name constraint on the operator's trust domain; short lifetimes (Section 5.4) | Tunnel certificates for every home of that operator: denial of service and metadata, not content |
| **Operator that tries to change what the household allows** | No message carries mandates, approver keys or issuer keys; a gateway accepts none (Section 5.7) | – |

## 10. Privacy considerations

*To be specified:* what an operator learns (home ID, server name, agent address, time, byte
counts) and how long it may keep it.

## Changelog

### Unreleased

- Skeleton: goal, terminology, operator metadata with schema and example, outline of pairing
  and issuance.
- Section 5 specified: directory, nonces and signed requests, errors, pairing (including a
  pairing code for an existing installation), installation, tunnel certificate, renewal and
  re-issuance within `max_offline_days`, key change, ACME support with a CAA binding to the
  gateway's ACME account, unpairing and blocking;
  schema `relay/schema/enrollment-v0.schema.json` with examples. Security considerations for
  Section 5.
