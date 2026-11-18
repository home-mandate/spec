# Coverage of the referenced RFCs

This file goes through every RFC that SPEC-v0 relies on, rule by rule, and says how the
conformance cases cover each rule. Every rule has one of four entries:

- **Cases**: the case IDs that fail for an implementation that breaks the rule.
- **Not testable**: the test interface (SPEC-v0 Section 10) cannot reach the rule. The reason
  is given.
- **Narrower**: the specification permits less than the RFC does, on purpose. The cases test
  the narrower rule.
- **Not followed**: the specification deliberately does something else. The reason is given.

Case IDs refer to the files in this directory: `c` cases-v0, `d` digest-v0, `i` invalid-v0,
`s` selection-v0, `g` signed-v0, `a` audit-v0, `v01` to `v99` succession-v0, `v1xx` audit-v1. The file belongs to issue
#112 and is kept up to date with the cases; a rule without an entry here is a gap.

## RFC 7493: The I-JSON Message Format

Section 3.1 item 1 of SPEC-v0 makes mandates I-JSON. The same holds for audit entries
(Section 9.4), signed payloads and key sets.

| Rule | Entry |
|---|---|
| 2.1 encoded in UTF-8 | Cases: `i176` to `i190` (invalid bytes, overlong forms, above U+10FFFF, CESU-8, UTF-16, UTF-32), `a231` to `a236`; a byte order mark: `i116`, `a18` |
| 2.1 no surrogates, encoded directly or escaped | Cases: `i24`, `i160`, `i161`, `i184`, `i185`, `a215`, `a218`, `a219`; a legal pair: `d52`, `a220` |
| 2.1 no noncharacters, encoded directly or escaped | Cases: `i123`, `i158`, `g24`, the noncharacter ranges among `i212` to `i289`; for existing logs the correction of Section 14: `a213`, `a214`, `s29` |
| 2.2 no numbers beyond double precision in magnitude or precision | Narrower: every number is an integer of magnitude at most 2^53 − 1. Cases: `i162`, `i163` (the examples of the RFC), `i106`, `c200`, `c201`, `c202`, `d56`; no fractions: `i105`, `i140`, `i143`, `c167`, `a224`, `a225`; a zero with a large exponent: `d53`, `a226`; `a228` |
| 2.3 no duplicate member names, also after escapes | Cases: `i06`, `i20`, `i159`, `a216`, `a217`, `g55` (protected header) |
| 2.3 member order has no meaning | Cases: `d06`, `d55` |
| 3 receivers may reject messages that are not I-JSON | Narrower: they MUST (Section 3.1). Cases: as above |
| 3 a way to signal the error to the sender | Not testable: a matter of the protocol around a mandate, not of the document. Section 9.1 records a rejected mandate with `mandate.rejected` |
| 4.1 top level an object or array | Narrower: always an object. Cases: `i18`; exactly one value: `i19`, `i25` |
| 4.2 Must-Ignore for unknown members | Not followed for mandates and audit entries: they are security policy and evidence, and an unknown member could change what they mean. A new member comes with a new type identifier (Section 14). Cases: `i01`; members an entry may not carry: `a56`, `a62`, `v116`. Followed for key sets: `g25`, `g26`, `g36` |
| 4.3 times in RFC 3339, upper case, offset included, seconds included | Cases: `i22`, `i63`, `i199`; see RFC 3339 below |
| 4.3 durations in the `duration` form of RFC 3339 appendix A | Narrower: `approval.timeout` is `PT[nH][nM][nS]` (Section 3.1 item 7). Cases: `i16`, `i64` to `i71`, `d16` to `d18` |
| 4.4 binary data in base64url | Followed in JWS and JWK (see RFC 7515). Digests are hexadecimal (Section 3.2) |

## RFC 8785: JSON Canonicalization Scheme (JCS)

The digest of a mandate (Section 3.2), the payload of a signed mandate (Section 7.1), the
chain of the audit log (Section 9.4) and the checkpoint payload (Section 9.5) are JCS.

| Rule | Entry |
|---|---|
| 3.1 input is I-JSON | Cases: see RFC 7493; a document that is not I-JSON has no canonical form and no digest (`v142`) |
| 3.1 strings are not altered, no Unicode normalization | Cases: `d66`, `d67` (the same text in NFC and NFD, two digests), `d62` |
| 3.2.1 no white space | Cases: `d06`, `d37`, `d61`; payloads: `g07` |
| 3.2.2.1 `null`, `true`, `false` | Cases: every log (`prev: null`); `d27` (`allow_critical: true`), `d43` (`enforce: false`) |
| 3.2.2.2 control characters as `\b \t \n \f \r` or `\u00xx` in lower case | Cases: `a243`, `a212` (line feed, escape character). Not testable in mandates: displayed text excludes control characters and identifiers are printable ASCII |
| 3.2.2.2 `"` and `\` escaped, everything else as is (DEL, U+2028, U+2029, `/`, non-ASCII) | Cases: `d07`, `d38` (escaped slashes in the input), `a243`, `a212` (`<`, `>`, `&`, U+202E) |
| 3.2.2.2 lone surrogates are an error | Cases: `i24`, `i160`, `i161`, `a215` |
| 3.2.2.3 numbers as ECMAScript writes them | Narrower: integers only, written in decimal without fraction or exponent (Section 3.2). Cases: `d10`, `d11`, `d29`, `d42`, `d53`, `d56` to `d58` (±(2^53 − 1), the form `E+`, `-0`), `a14`, `c166`, `c203`. Fractions and floating point do not occur |
| 3.2.2.3 NaN and Infinity are an error | Not testable: JSON cannot write them; `i162` (1E400) is rejected before canonicalization |
| 3.2.3 members sorted by UTF-16 code units, recursively | Cases: `d06`, `d55` (digits, underscore and letters). Not testable beyond ASCII: no document of this version has a member name outside ASCII, so UTF-16 order and code point order never differ |
| 3.2.3 array order kept | Cases: implicit in every case with several rules, actions or entries; `c82` shows that rule order matters to the evaluation |
| 3.2.4 output in UTF-8 | Cases: `d07`, `d21` to `d23`, `d36`, `d52`, `d54`, `d66`, `d67` |
| 5 verify I-JSON, then the content, then the signature | Cases: `g10` (valid signature over an invalid mandate), `g24`, `g07` |

## RFC 3339: Date and Time on the Internet: Timestamps

Section 3.1 item 0 applies to every `format: date-time` in mandates and audit entries and,
from v0.2 on, to the `time` of a request (Section 10.2).

| Rule | Entry |
|---|---|
| 5.6 `date-time` with `full-date`, `T`, `full-time` | Cases: `i08`, `i23`, `i63`, `i198` (a five-digit year), `c243` to `c251` |
| 5.6 `time-secfrac` with at least one digit | Cases: `i195`. Narrower: at most 9 digits: `i59`, `c260`, `c261`, `d19` |
| 5.6 `time-numoffset` `+hh:mm` or `-hh:mm`, or `Z` | Cases: `i22`, `i196` (`+0100`), `i113`, `i114`, `i202`, `c243` to `c246`, `d20`, `d34` |
| 5.6 NOTE: `T` and `Z` may be lower case | Narrower: upper case only, as RFC 7493 section 4.3 recommends. Cases: `i63`, `i199` |
| 5.6 NOTE: a space instead of `T` by agreement | Not followed: no such agreement. Cases: `i197`, `s30` |
| 5.7 month 01 to 12, day by month and leap year, hour 00 to 23, minute 00 to 59, offset hour 00 to 23 | Cases: `i200`, `i201`, `i23`, `i115`, `i191` (1900), `d35`, `d59` (2000), `i192`, `i193`, `i202`, `i11` (time window), `c250` |
| 5.7 second 60 only for a leap second | Narrower: no leap seconds (Section 3.1 item 0). Cases: `i26`, `a221` to `a223`; second 61: `i194` |
| 4.3 offset `-00:00`, unknown local offset | Not followed: forbidden, because it says nothing about the local time a window needs. Cases: `i61`, `i62`, `c259`; `+00:00` is permitted: `d20`, `c262` |
| 5.6 year 0000 | Narrower: forbidden (Section 3.1 item 0). Cases: `i60`, `c258`; the earliest point in time: `c257`; the latest: `d60` |
| 5.1 comparison as text only when the offsets are the same | Narrower: always as points in time, to the nanosecond (Section 3.1 item 0). Cases: evaluation `c18` to `c22`; selection `s10` to `s12`, `s32` to `s35`; succession, where `expires` and `valid_from` move earlier or later (Section 3.5), `v24` to `v28`; `d19` |

## RFC 9562: Universally Unique IDentifiers (UUIDs)

| Rule | Entry |
|---|---|
| 4 string form, 8-4-4-4-12 hexadecimal digits | Cases: `a247` (no hyphens), `a185` (`request.group`) |
| 4 hexadecimal digits are case-insensitive on input | Narrower: lower case only, so that an `id` compares as a string. Cases: `a245` |
| 4.1 variant bits `10` | Cases: `a246`; `log_id` in audit/v1: `v140` |
| 4.2 version field; 5.7 version 7 for the `id` of an entry | Cases: `a244`; a `log_id` of version 4 or 7 from audit/v1 on: `v140` |
| 5.7 the timestamp of version 7 orders entries in time | Not followed: the `id` is opaque, the order of a log is its `seq` (Section 9.4), and a verifier never reads a time from an `id` |
| 6.1 uniqueness | From audit/v1 on, an `id` does not repeat: `v139`, `v141`; version 0 is not held to it: `a237` |

## RFC 7515: JSON Web Signature (JWS)

Section 7.1 (signed mandates) and Section 9.5 (checkpoints, detached payload).

| Rule | Entry |
|---|---|
| 3.1 and 7.1 compact serialization | Narrower: the only serialization. Not testable otherwise: the test interface passes a string, and JSON serialization has no field to arrive in |
| 2 base64url without padding, line breaks or other characters | Cases: `g13`, `g14`, `g15`, `g31`; one spelling, unused bits zero (RFC 4648 section 3.5): `g51` to `g54`, `a242` |
| 4 protected header is I-JSON | Cases: `g55` |
| 4 and 4.1 header members; the names are case-sensitive | Narrower: exactly `alg` and `kid`. Cases: `g16`, `g17`, `g62` (`jwk`); checkpoints: `a240` |
| 4.1.1 `alg`, compared exactly | Cases: `g06`, `g20`, `g75` (`eddsa`); checkpoints: `a239` |
| 4.1.2 to 4.1.7 `jku`, `jwk`, `kid`, `x5u`, `x5c`, `x5t` and key selection | Narrower: keys never come from the object (Section 7.1). Cases: `g62` (`jwk`); the other members are refused like `typ`: `g17`. `kid`: `g11`, `g56` to `g58` |
| 4.1.11 `crit` must be understood | Narrower: refused as a member (Section 7.1). Cases: `g18`, `a240` |
| RFC 7797 `b64` (unencoded payload) | Narrower: refused as a member like any other (Section 7.1). Cases: `g17`, `g18` |
| 5.2 verification: payload, signature, key; three segments, none empty | Cases: `g03`, `g04` (no signature), `g05` (no payload), `g07`, `g08`, `g10` |
| Appendix F detached content | Cases: checkpoints `a39` to `a49`, `a194`, `a239` to `a242`, `v103`, `v124` |
| 10 security considerations (key origin, algorithm confusion) | Cases: `g08` (keys of another issuer), `g20` (`alg` and key type), `g62` |
| a limit on the size of the protected header | Narrower: 256 bytes (Section 7.1). Cases: `g43`, `g44` |

## RFC 7517: JSON Web Key (JWK)

| Rule | Entry |
|---|---|
| 4 unknown members are ignored; member names are case-sensitive | Cases: `g25`, `g26`, `g27`, `g28`, `g29`, `g30`, `g36` |
| 4.1 `kty` | Cases: `g29`, `g70` |
| 4.2 `use` | Cases: `g37`, `g38` |
| 4.3 `key_ops` | Cases: `g39`, `g40` |
| 4.4 `alg` | Cases: `g41`, `g42` |
| 4.5 `kid`; keys in a set SHOULD have distinct `kid` values | Narrower: every key has a `kid` of the pattern, a `kid` repeats in no key set, and a set that breaks this verifies nothing. Cases: `g59`, `g60`; the pattern: `g57`, `g58`, next to the signing key `g91`, `g92`; no `kid` or one that is not a string: `g93`, `g94` |
| 5 a JWK Set has a `keys` member | Cases: `g27`, `g30` |
| 5 readers SHOULD skip keys they cannot use | Not followed: a set with such a key verifies nothing, so that a verifier never trusts less or more than the household configured (Section 7.1). Cases: `g38`, `g40`, `g42`, `g63` to `g65`, `g70`; next to the signing key, one case for each kind of key: `g76` to `g96`. Followed for a key whose point is not on its curve, which verifies nothing and so changes no verdict: `g71`, `g74`, `g99`, `g100` |
| a key set is I-JSON, at most 65 536 bytes | Narrower (Section 7.1). Cases: `g97` (a member twice in a key), `g98` (`keys` twice), `g101` (65 537 bytes) |
| 9.2 a private key is not published | Cases: `g32`, `g33` (RFC 8037 section 2) |

## RFC 7518: JSON Web Algorithms (JWA), Section 3

| Rule | Entry |
|---|---|
| 3.1 `none` | Not followed: never accepted. Cases: `g06`, `a239` |
| 3.4 ES256: R and S of 32 octets each, concatenated | Cases: `g02`, `a42` (valid, `requires: ES256`), `g67`, `g68`, `g69` |
| 3.4 verification of ECDSA: r and s between 1 and n − 1 | Cases: `g66` (r = s = 0), `g72` (r = n), `g73` (s = 0) |
| a P-256 key is a point of the curve | Cases: `g74`; next to the signing key, the set stays usable: `g100` |
| ECDSA malleability: both s and n − s verify | Narrower: only the lower s (Section 7.1). Cases: `g12`, `a241` |
| other algorithms (HS256, RS256, PS256, …) | Not followed: only EdDSA (MUST) and ES256 (MAY). Cases: `g06`, `g20` |

## RFC 8037: CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE

| Rule | Entry |
|---|---|
| 2 `kty: OKP` with `crv` and `x` | Cases: `g01`, `g63` (`X25519`) |
| 2 `x` is the public key, 32 octets for Ed25519 | Cases: `g64`, `g65`, `g54` |
| 2 `d` makes it a private key | Cases: `g32`, `g33` |
| 3.1 `alg: EdDSA` with Ed25519 | Cases: `g01`, `g41`, `g20` |
| Ed448 | Not followed: not supported in this version; a key with `crv: Ed448` cannot be used, as `g63` shows for `X25519` |

## RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA), Section 5.1

| Rule | Entry |
|---|---|
| 5.1.3 decoding: y < p | Cases: `g21` (R), `g50` (the key; the equation holds, so only this check rejects it). Not testable for a key of prime order written with y ≥ p: nobody can sign for such a key, so every verifier rejects its signatures for another reason |
| 5.1.3 decoding: a point exists for y | Cases: `g71`; next to the signing key, the set stays usable: `g99` |
| 5.1.3 decoding: x = 0 with the sign bit set | Cases: those encodings are in the list of Section 7.1 and rejected as keys of small order (`g34` shows the list at work) |
| 5.1.7 S < L | Cases: `g19` |
| 5.1.7 signature of 64 octets | Cases: `g61` |
| 5.1.7 the cofactored equation is sufficient, the cofactorless one MAY be used | Narrower: cofactorless only, a MUST (Section 7.1). Cases where only the cofactored equation holds: `g46`, `g47` (only that), `g48` (also an R of small order) |
| keys of small order | Narrower: rejected (Section 7.1). Cases: `g34`, `g35`, `g50` |
| keys of mixed order | Followed: they are keys, the cofactorless equation decides. Cases: `g45` (verifies), `g46` (does not) |
| R of small order | Narrower: rejected even where the equation holds (Section 7.1). Cases: `g49`, `g48` |
| 5.1.6 signing | Cases: every valid case, signed with the test key of RFC 8037 appendix A |

## SPEC-v0 Section 3.1 item 8 and data/forbidden-codepoints-v0.json

| Rule | Entry |
|---|---|
| no code point listed under `forbidden` | Cases: the first and the last code point of every range, in `display_name`: `i212` to `i289` (lone surrogates through `i24`, `i160`, `i161`); in other fields: `i31` to `i34`, `i73` to `i76`, `i78`, `i82`, `i118` to `i123`, `i152`, `i153`, `i164` to `i175`, `a21` to `a23`, `a68`, `a74`, `a227` |
| the code points next to a forbidden range are permitted | Cases: `d64` (each neighbour that is not forbidden itself) |
| not beginning with a code point listed under `not_first` | Cases: the first code point of every range that is not also forbidden, at the beginning: `i290` to `i616`; `i124` to `i126` |
| `not_first` code points after another code point are permitted | Cases: the first and the last code point of every range after a letter: `d65`; `d23`, `d40`, `d62` |
| no space at the beginning or end; U+0020 the only white space | Cases: `i72`, `i77`, `i78`, `i83`, `i84`, `i118`, `i119`, `a22`; spaces inside: `d39` |
| joiners only between two other code points | Cases: `i79`, `i80`, `i81`; permitted: `d21`, `d22` |
| lengths in code points, not bytes, UTF-16 units or graphemes | Cases: `d36`, `i117`, `d62`, `i204`, `d63` |
| minimum and maximum of each field | Cases: `display_name` `d36`, `i117`, `i207`; `name` `d63`, `i205`, `i155`; `note` `d63`, `i154`, `i206`; `created_by` `d49`, `i208`, `i210`; approvers `d49`, `i209`, `i211` |
| Section 3.1 item 5: the size counts bytes as received | Cases: `d61` (262 144 bytes), `i203` (262 145 bytes, fewer code points), `i36` |
| homoglyphs | Not testable: Section 3.1 item 8 says the rule cannot prevent them; user interfaces show `client_id` next to `display_name` |
