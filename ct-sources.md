<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Certificate Transparency sources (informative)

This list helps implementations choose the sources of their Certificate Transparency monitoring
(SPEC-v0 Section 11.7 item 7). It is informative: conformance does not depend on it, and a source
that is not listed may be used just as well, as long as the rules of that item hold.

Section 11.7 item 7 asks for at least two independent sources. Services of one provider count as
one source, and a source run by whoever runs the way in (the operator of a relay) does not count. A source is suitable when it

1. finds certificates by a name and by the wildcards that cover it (a search by the exact name
   alone does not meet the item);
2. reports precertificates as well as certificates, with the time of the first log entry, the
   names, the validity and the public key, or the certificate itself, from which these follow;
3. can be queried by a household without an agreement of its own, at least once an hour.

| Source | Provider | Search | Note |
|---|---|---|---|
| Cert Spotter API (`api.certspotter.com`) | SSLMate | by name, with `match_wildcards` | usable without a key within its published limits; prefer IPv6, because households behind carrier-grade NAT share an IPv4 address and its limits |
| crt.sh | Sectigo | by name; wildcards by a second query for `*.` and the parent | may answer slowly or not at all; a failed query counts as no answer |

The logs themselves are a source too, if the implementation reads every log that the browsers'
log lists accept and verifies their signed tree heads. A single log is not: it sees only the
certificates submitted to it.

Changes to this list are listed in the Changelog of SPEC-v0.md.
