<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# What an implementation declares

The conformance cases test what an implementation computes. They cannot test what it does
around that: what it stores, executes, records, shows or keeps apart. SPEC-v0 Section 8.1 asks an
implementation to state, for each obligation below that applies to it, how it meets it. This list
names them, with their sections; the text of SPEC-v0 decides. An implementation that publishes its
declaration copies the list and adds, for each row, how it meets the obligation, or why the row
does not apply (for example: it offers no audit mode, or it is not reachable from outside).

A claim of conformance to a class (Section 8.1) does not need this declaration. A claim that an
implementation as a whole follows the specification does.

## Mandates and resources (Sections 3 and 4)

| Section | Obligation |
|---|---|
| 3.1 | Reject invalid mandates when they are stored; never store or evaluate one |
| 3.4 | Tell the household which mandates are affected when an identifier or area a rule names changes or disappears, or a resource leaves or enters such an area |
| 3.4 | Treat a resource that newly comes under an `allow` rule as critical until a human has seen it, and report it |
| 3.5 | Remember the highest version of every mandate `id`, also after revocation and removal; a weakening successor, audit mode and a successor of a revoked mandate take effect only after a human confirmed them |
| 4 | Take category, areas, critical marking, time, time zone and status from the PEP's own sources, never from the agent |
| 4 | Resolve the resource the agent names to its identifier in the directory; deny with `unknown_resource` when a name fits more than one resource |
| 4 | Let the household mark resources as critical |
| 4.4 | Execute a request for several resources on exactly the resources evaluated, each named to the platform; record each as its own `decision` entry, with one `request.group` where one entry records the outcome of the whole request |
| 4.4 | Resolve a group whose members the platform reports to them and execute on the members; treat a group whose members are unknown as critical |

## Signed mandates and the PDP (Sections 6 and 7)

| Section | Obligation |
|---|---|
| 6 | If PEP and PDP are separate: exactly one holds the directory and both know which; the connection is authenticated in both directions and protected against modification and replay; the PDP answers only callers it authenticated, never agents, and only for the principals it serves for that caller |
| 6 | A PEP obtains a confirmation for `outcome: ask` and for `confirm: true`, and executes only after a positive one |
| 7.1 | Configure the keys of an issuer before any mandate is verified, never fetch them from a location a mandate names; decide per issuer for which principals and agents it may issue ; never accept a key trusted for one household for another |
| 7.1 | Remember by which `kid` each stored mandate was accepted; when a key stops being trusted, every mandate accepted only by it loses its effect or is confirmed again by a human |
| 7.1 | Record every issuer and key that is trusted, untrusted, added or removed (`issuer.changed`); a key whose bytes change under its `kid` is removed and added |
| 7.1 | Never sign mandates and checkpoints with the same key; which optional algorithms (ES256) the implementation supports |

## Audit log (Section 9)

| Section | Obligation |
|---|---|
| 9 | Keep an audit log; store what will be recorded about a request durably before the command is dispatched; deny with `denied_by: audit` when that is not possible; record an intent without result as `failed` with `outcome_unknown` after a restart |
| 9.1 | One log for each household; no tokens, nonces, credentials or content of a mandate or template in an entry; `received` never used to match a mandate, a version or a confirmation |
| 9.1 | Show the values of `request`, the `names` and `issuer` of a certificate and the values of `relay` as untrusted text wherever entries are rendered for a human |
| 9.2 | Write every event of Section 9.2 that applies to the implementation; limit the documents taken from each source |
| 9.3 | Keep every mandate version as long as entries refer to its digest; delete only the oldest entries, after a `log.truncated` entry |
| 9.4 | Write new entries as I-JSON with numbers below 2^53; call a log damaged only for `integrity_broken_at`; never refuse to start or stop writing because of `conformance_broken_at` or `unknown_version_at` alone ; show `conformance_broken_at` as a fault of the software that wrote the entry and `unknown_version_at` as a newer version the tool cannot check |
| 9.5 | Keep the checkpoint key where whoever can write the log cannot read it, or say that the platform offers no such place; sign only the digest of the last entry as it was appended, never one read or verified from the log file, and keep its `seq` and digest with the key; never sign a `seq` that is not higher; a checkpoint after every `log.truncated` entry, after 1000 entries and within 24 hours; a new log with a new `log_id` after a restore that ends before the highest signed `seq` ; after a restart continue the log only from the kept state, append the same entry again only from a write-ahead record of its bytes, and otherwise start a new log |

## Obligations of the PEP (Section 11)

| Section | Obligation |
|---|---|
| 11.1 | Every item of Section 11.1: how confirmations are requested, bound, answered and checked |
| 11.1, 11.2 | The rate limit, counted across restarts, and the limits on waiting approval requests, for each agent and for all agents together |
| 11.3 | Revocation, emergency stop, removal and reconnection, and what each withdraws |
| 11.4 | The clock rules: the reference time from the log, the last checkpoint and a mark kept outside the log, in the PEP and in a PDP with its own clock; a clock that never runs backwards for timeouts, the rate limit and DPoP proofs; the handling of the directory, renamed resources included |
| 11.5 | What the agent is told of its limits, if anything |
| 11.6 | Audit mode, if offered: how it is switched on and shown |
| 11.7 | If reachable from outside: every item, Certificate Transparency monitoring and the alarms included |
| 11.7 | If reachable from outside: the channel outside the implementation's own pages through which an alarm and the state `unavailable` of Certificate Transparency monitoring reach every administrator, and that an alarm stays shown across restarts until acknowledged; a key presented under the public origin that differs from the current one is taken only when the administrator accepts it |
| 11.8 | What `read` returns; if repeated reads share one entry: the count stored before each read is executed, the entry written within 60 seconds, and written after a crash at the next start |

## Test interface (Section 10)

| Section | Obligation |
|---|---|
| 10.1 | The test interface is not offered in operation: not in a release build, or only after an explicit start option that is off by default; its state never mixes with the household's mandates and log |
| 10.3 | The control resource of the HTTP binding requires authentication, except where Section 10.3 allows otherwise in a test run |

## Versions (Section 14)

| Section | Obligation |
|---|---|
| 14 | Which audit versions the implementation writes, and since which release |
| 14 | Write a new audit version only once the implementation's own verification, display and export read it; a checkpoint of the older version before the first entry of the newer one; never append to a log that holds entries of a newer version than the implementation writes |
| 14 | Do not write entries with a deviation listed in `data/corrections-v0.json` |
| 14 | Never rewrite a stored or signed mandate into another format, and never rewrite an audit log: it continues in the newer version |

## Rules the test interface cannot reach

`RFC-COVERAGE.md` lists three rules that no document of this version can exercise through the
test interface: member order by UTF-16 code units beyond ASCII, control-character escapes in
mandates, and keys of prime order written non-canonically. An implementation that claims to
follow them states how, for example by naming the library and its tests.
