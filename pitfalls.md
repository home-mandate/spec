<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Pitfalls for implementers (informative)

Each of these has cost an implementer time. Every one is covered by conformance cases, so a
mistake shows up as a failed case; this page says why the case fails. It is informative:
SPEC-v0.md decides.

## Patterns that end before a final line feed

In Python, `$` in a regular expression also matches before a line feed at the end of the string,
so `re.match(r"^[a-z0-9-]+$", "r-1\n")` succeeds. The patterns of the schemas apply to the whole
string: use `re.fullmatch`, or end the pattern with `\Z`. Perl, PCRE and Ruby behave alike by
default; JavaScript without the `m` flag and Go do not.

Cases: `i37` to `i42`.

## JCS sorts members by UTF-16 code units

RFC 8785 sorts member names by their UTF-16 code units. Sorting by code points (Python's `sorted`)
or by UTF-8 bytes (Go's `sort.Strings`, Rust's `BTreeMap`) gives the same order for every name in
the Basic Multilingual Plane, but not for a name with a character above U+FFFF next to one between
U+E000 and U+FFFF. No member name of this version leaves ASCII, so the cases cannot show it; a
library that implements RFC 8785 gets it right.

Cases: `d06`, `d55`.

## Decoders that remove a byte order mark

A byte order mark before a mandate or an audit entry makes it invalid. `TextDecoder` in
JavaScript removes it by default (`new TextDecoder("utf-8", { ignoreBOM: true })` keeps it), and
so does Python's `utf-8-sig` codec. Check the bytes before decoding them.

Cases: `i116`, `i186` to `i190`, `a18`.

## Lenient time parsers

A point in time is RFC 3339 as Section 3.1 item 0 narrows it. Python's `datetime.fromisoformat`
accepts any single character instead of `T`, a comma before the fraction and times without
seconds; `Date.parse` in JavaScript accepts more still. Check the text against the grammar first,
then convert it.

Cases: `i63`, `i197`, `c247`, `s30`.

## Lenient base64url decoders

A signed object has exactly one spelling: base64url without padding, line breaks or other
characters, with the unused bits of the last character set to zero (RFC 4648 section 3.5). Many
decoders accept padding, skip characters they do not know or ignore the unused bits, among them
Node's `Buffer.from(s, "base64url")`, Python's `base64.urlsafe_b64decode` and Go's
`base64.RawURLEncoding` without `.Strict()`. Decode strictly, or encode the result again and
compare it with the input.

Cases: `g13` to `g15`, `g31`, `g51` to `g54`, `a242`.

## Time zone names that match without regard to case

`Europe/BERLIN` is not a name of the time zone database, but `Intl.DateTimeFormat` in JavaScript
accepts it and returns `Europe/Berlin`, and Python's `zoneinfo` finds it on a file system that
ignores case (macOS, Windows). Compare the spelling yourself. `timezone-names.json` lists the
names of one release of the database in the form of Section 4.2, for a runtime without an exact
list of its own.

Cases: `c132`.

## Ed25519 libraries disagree

Libraries accept different Ed25519 signatures and keys, and the same library can change between
patch versions:

- most libraries import a public key that is not on the curve without complaint; such a key
  verifies nothing;
- some reject a signature whose `R` is of small order and some accept it; OpenSSL has done both;
- libraries that follow ZIP 215 verify with the cofactor and accept signatures that a verifier
  without the cofactor rejects.

Section 7.1 therefore fixes the checks on the bytes of keys and of `R`, a few constant
comparisons, and requires verification without the cofactor. Do not rely on the library alone.

With a library that verifies with the cofactor but offers point arithmetic, verification without
the cofactor takes a few lines:

1. Check the bytes as Section 7.1 asks: the signature has 64 octets, `S` (its last 32 octets,
   little-endian) is less than the group order `L`, and neither the key `A` nor `R` (the first
   32 octets) is one of the encodings of small order or has y ≥ p.
2. Decode `A` into a point; if no point exists, the signature does not verify.
3. Compute `k` = SHA-512(`R` ‖ `A` ‖ message), read as a little-endian integer, modulo `L`.
4. Compute the point [`S`]B − [`k`]A, with B the base point, and encode it as 32 octets.
5. The signature verifies exactly if that encoding equals `R`, byte for byte.

Comparing the encoding with `R` is the equation without the cofactor; it is what Go's
`crypto/ed25519` does. A library whose scalar multiplication refuses 0 needs its unsafe
variant for `S` = 0, which step 1 does not exclude.

Cases: `g45` to `g75`, `g76` to `g105` for key sets.

RFC 9864 names EdDSA with Ed25519 `Ed25519`. A key may carry that name in `alg`; the header of a
signed mandate or a checkpoint still names `EdDSA`, and a header with `"alg":"Ed25519"` is
rejected (Section 7.1). A signer that follows RFC 9864 has to write `EdDSA` in the header.

## A verifier without ES256

ES256 is optional (Section 7.1), and the Go reference always has it. Cases `g99` and `g100` put a
key that is not on its curve next to the signing key; a verifier without ES256 takes the other
path of Section 7.1 for the P-256 one, and only its own run of the cases shows that it keeps the
key set usable. Passing them in the reference proves nothing about that path. Case `g104` shows
that a P-256 key with a restriction still counts for such a verifier.

## Punycode without IDNA

A verifier of an audit log checks a public origin with the Punycode round trip of Section 11.7
item 1 and MUST NOT apply IDNA. Node, Python and browsers offer IDNA (`url.domainToASCII`,
`encodings.idna`, the URL parser), which maps and validates labels, but no plain Punycode of RFC
3492; Python's `"…".encode("punycode")` is plain Punycode without the `xn--` prefix. Where none
is at hand, RFC 3492 takes about sixty lines. Valid here means only the one form: a label that
survives the round trip can still be one that IDNA refuses and that no resolver will find. Cases: `o26`, `o39` to `o44`, and the public
origins in `audit-v1.json`.
