# mandate-spec v0 (Draft)

Status: **Working draft**; it will be frozen only after deployment in real households.
License of this document: CC BY 4.0. Schema, examples, conformance cases and code: Apache 2.0.
Reference implementation: Home-Mandate. Changes are listed in the Changelog at the end.

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT" and "MAY" in this document are to be
interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in
all capitals.

## 1. Goal

A vendor-neutral format that describes **what a software agent may do on behalf of a
household**, and an evaluation rule that yields the same result in every implementation. The
specification builds on existing standards and defines only what is missing:

| Purpose | Standard |
|---|---|
| Decision interface | OpenID AuthZEN Authorization API 1.0 |
| Transport of the mandate in the OAuth flow | Rich Authorization Requests (RFC 9396), `authorization_details` |
| Agent identity | OAuth 2.1 client ID (for MCP: Client ID Metadata Document) |
| Device vocabulary | own categories with an informative mapping to Matter device types |

Newly defined are: the mandate data model, the third decision `ask`, conditions,
protection classes and the evaluation rule.

## 2. Terminology

- **Principal:** the household or person on whose behalf the agent acts.
- **Agent:** software that requests actions, identified by its OAuth client ID.
- **Resource:** a single device or entity.
- **Action:** what is to be done with the resource, taken from the vocabulary of its category.
- **Decision:** `allow` (execute immediately), `ask` (a human must confirm), `deny` (reject).

## 3. Data model

Machine-readable: `schema/mandate-v0.schema.json`. The schemas in `schema/` are normative;
this text and the schemas MUST agree, and any contradiction is an error in the
specification. Summary:

```
Mandate
├── type          "https://mandate-spec.org/mandate/v0"
├── id            unique ID
├── principal     "household:<id>" or "person:<id>"
├── agent         { client_id, display_name }
├── rules[]       rule
│   ├── id
│   ├── resource  selector: entity_id | category | area (at least one) or any: true alone
│   ├── actions[] actions from the vocabulary or "*"
│   ├── decision  allow | ask | deny
│   ├── conditions? { time_window, weekdays }
│   ├── approval?   { timeout, approvers }   only with ask
│   └── allow_critical?  true, required for allow on critical actions
├── default       always "deny" in v0
├── approval      default for ask: { timeout, approvers }
├── limits        { max_actions_per_hour }
├── valid_from, expires?
└── created_by, created_at
```

### 3.1 Validity of a mandate

A mandate is valid if it conforms to the schema **and** additionally:

0. all fields with `format: date-time` are valid RFC 3339 timestamps with an offset
   (implementations MUST validate `format`, not merely treat it as an annotation);
   leap seconds (`:60`) are not permitted;
1. it is I-JSON as defined in RFC 7493: valid UTF-8, no lone surrogates (e.g. a
   standalone `\ud800`), no JSON object with a duplicate key, exactly one JSON value;
2. all rule `id`s within the mandate are distinct;
3. for every `time_window`, start and end are distinct;
4. every rule whose `resource` names a category from Section 5 contains only actions from that
   category's vocabulary or `"*"` (e.g. `unlock` with `category: light` is invalid).
   If the rule names an extension category whose vocabulary the implementation does not
   know, this check is skipped; such rules never match during evaluation (Section 4);
5. it is at most 262 144 bytes (256 KiB) in size;
6. `expires`, if present, is later than `valid_from`;
7. every `approval.timeout` is between 10 seconds and 1 hour (both inclusive);
8. `agent.display_name`, `created_by` and all `approvers` contain no characters of the
   Unicode categories Cc, Cf, Zl and Zp (control characters, bidirectional and
   invisible format characters, line and paragraph separators). These texts are displayed
   to humans, for example in an approval request, and MUST NOT be able to mislead them.

Implementations MAY reject JSON input with a nesting depth greater than 32 before
validating it against the schema; valid mandates never reach this depth.

Implementations reject invalid mandates when they are stored. If an invalid mandate is
nevertheless evaluated, the result is always `deny`.

Revocation of a mandate is not a field of the mandate but a state that the
implementation maintains and passes to the evaluation.

### 3.2 Digest of a mandate

Each version of a mandate is uniquely identified by its digest:

```
digest = "sha256:" + hex(SHA-256(JCS(mandate)))
```

- `JCS` is the canonical JSON form defined in RFC 8785: sorted keys, no whitespace,
  a fixed representation of strings and numbers.
- The digest is computed over the valid mandate (Section 3.1), not over the stored
  bytes. Key order and whitespace therefore do not change the digest; any change in
  content does.
- `hex` produces lowercase letters, 64 characters.

In the audit log (Section 9), the digest refers to the version on which the decision was
based, without writing the content of the mandate to the audit log.

## 4. Evaluation rule

Input: mandate, resource (entity ID, category, area), action, point in time,
household time zone, status of the mandate (`active` or `revoked`).

**Origin of inputs:** The PEP determines the category and area from its own resource
directory, the point in time from its own clock, the time zone from the household
configuration and the status from its own mandate management. It takes none of these
from the agent; only the requested entity ID and action originate from the agent.

0. Pre-check, each case → `deny`:
   - the mandate is invalid (Section 3.1);
   - the request is invalid: the entity ID is missing or does not match the pattern of
     `entity_id` in the schema, a given area does not match the pattern of `area`,
     the category is missing, the point in time or the time zone is invalid or unknown, or the
     status is neither `active` nor `revoked`;
   - the category is neither listed in Section 5 nor an extension whose vocabulary
     the implementation knows;
   - the action does not belong to the vocabulary of the resource's category.
1. If the mandate is revoked, not yet valid or expired → `deny`.
   It is valid for points in time `t` with `valid_from ≤ t < expires` (without `expires`:
   `valid_from ≤ t`). Points in time are compared, not clock times.
2. Collect all rules whose `resource` matches the resource **and** whose `actions` contain the
   action **and** whose `conditions` are satisfied at the point in time.
   - `resource` matches if **all** specified fields match
     (e.g. `category: light` and `area: wohnzimmer` = lights in the living room).
     `any: true` matches every resource. Comparison is exact per character, case-sensitive
     and without normalization.
   - `"*"` in `actions` contains every action, including critical ones.
   - `read` is an action in its own right. Write permissions do not include read permissions.
3. No rule found → `default` (`deny`).
4. Otherwise the **most restrictive** decision wins: `deny` over `ask` over `allow`.
5. Protection class: If the action is **critical** (Section 5) and the result is `allow`, but
   not **every** one of the matching `allow` rules carries `allow_critical: true` → the result becomes `ask`.
   For non-critical actions, `allow_critical` has no effect.

The rule is deliberately simple: whoever allows something broadly and denies individual items
gets the denial. Whoever sets something broadly to `ask` and allows individual items gets `ask`.
When in doubt, the safer side always wins.

`limits` are not part of the evaluation. The PEP enforces the rate limit.

### 4.1 Result

In addition to the decision, the evaluation returns:

- **`reason`:** exactly one reason code. If several reasons apply, the first one in
  the following order applies:

  | Code | Decision | Meaning |
  |---|---|---|
  | `invalid_mandate` | deny | mandate invalid (Section 3.1) |
  | `invalid_request` | deny | request invalid (step 0, second item) |
  | `unknown_category` | deny | category neither in Section 5 nor a known extension |
  | `unknown_action` | deny | action not in the category's vocabulary |
  | `revoked` | deny | mandate revoked |
  | `not_yet_valid` | deny | point in time before `valid_from` |
  | `expired` | deny | point in time at or after `expires` |
  | `no_match` | deny | no rule matches, `default` |
  | `critical_demotion` | ask | `allow` became `ask` per step 5 |
  | `rule` | allow, ask, deny | decision of a rule per step 4 |

- **`mandate_digest`:** digest of the evaluated mandate (Section 3.2); absent for
  `invalid_mandate`.
- **`rule_id`:** the first rule in document order that carries the final decision.
  For step 5, this is the first matching `allow` rule without `allow_critical`.
  For the pre-check, step 1 and step 3, there is no `rule_id`.
- **Approval settings** (only for `ask`): the `approval` of the first matching `ask` rule in
  document order that has its own `approval`, otherwise the `approval` of the mandate.

### 4.2 Conditions

All conditions of a rule MUST be satisfied. They are checked in **household local
time**: the point in time is converted to the household's time zone.

- The time zone is an identifier from the IANA time zone database, exact per character and
  case-sensitive: `UTC` or the form `Area/Location` (e.g. `Europe/Berlin`,
  `America/Argentina/Buenos_Aires`, `Etc/GMT+9`), where each part begins with an uppercase letter
  and contains only `A–Z`, `a–z`, `0–9`, `_`, `-`, `+`; at most 64 characters.
  Other names (including `Local`, `localtime` or abbreviations such as `CET`) and names that the
  implementation does not know result in `invalid_request`.
- If no time zone is given, the offset with which the point in time is expressed applies.
- For the comparison, the hour and minute of local time are used; seconds and fractions are
  truncated (23:58:59 is 23:58).

- `time_window`: `"HH:MM-HH:MM"`, minute precision, start inclusive, end exclusive.
  `"06:00-22:00"` matches 06:00 through 21:59. If the start is greater than the end, the
  window spans midnight: `"22:00-06:00"` matches from 22:00 and before 06:00.
  During daylight saving time transitions, the clock time displayed in the household counts;
  an hour that occurs twice matches both times.
- `weekdays`: list of `mon` … `sun`. The weekday of the point in time in local time is
  decisive, including for windows spanning midnight (Friday 22:00 to Saturday 02:00 with
  `weekdays: ["fri"]` matches only until midnight).

## 5. Vocabulary v0

The columns Category, Actions and Critical are normative. The columns for Home Assistant
and Matter are informative: they show how a platform can map its devices.

| Category | Actions | Critical | Home Assistant (informative, reference implementation) | Matter (informative, to be verified) |
|---|---|---|---|---|
| `light` | read, turn_on, turn_off, set | – | `light.*` | OnOffLight, DimmableLight |
| `switch` | read, turn_on, turn_off | – | `switch.*` | OnOffPlugInUnit |
| `climate` | read, set_temperature, set_mode | – | `climate.*` | Thermostat |
| `cover` | read, open, close, stop, set_position | – | `cover.*` (excluding gate/garage) | WindowCovering |
| `gate` | read, open, close | open | `cover.*` with device_class `garage` or `gate` | – |
| `lock` | read, lock, unlock, open | unlock, open | `lock.*` | DoorLock |
| `alarm` | read, arm, disarm | disarm | `alarm_control_panel.*` | – |
| `camera` | read, snapshot | snapshot | `camera.*` | Camera |
| `media` | read, turn_on, turn_off, play, pause, set_volume | – | `media_player.*` | – |
| `sensor` | read | – | `sensor.*`, `binary_sensor.*` | – |
| `scene` | read, activate | – | `scene.*` | – |
| `script` | read, run | run | `script.*` | – |
| `other` | read, set | set | all other domains | – |

`script.run` and `other.set` are critical because scripts and unknown entities can have
arbitrary consequences, including opening doors.

Extensions for other platforms receive their own namespaces, e.g.
`paperless:document` with `read`, `tag`, `delete`. An extension defines its vocabulary and
its critical actions. If an implementation does not know the vocabulary of an extension,
every request for a resource of that category is `deny`.

## 6. AuthZEN mapping

The PEP queries the PDP in accordance with AuthZEN Authorization API 1.0:

```json
POST /access/v1/evaluation
{
  "subject":  { "type": "agent", "id": "https://example-agent.local/client.json",
                "properties": { "principal": "household:hm-7f3a" } },
  "action":   { "name": "unlock" },
  "resource": { "type": "lock", "id": "lock.haustuer",
                "properties": { "area": "flur" } },
  "context":  { "time": "2026-10-12T21:14:03+02:00" }
}
```

AuthZEN only knows `true` or `false`. The third decision is conveyed in the response
context:

```json
{ "decision": false,
  "context": { "outcome": "ask", "reason": "rule", "rule_id": "r-locks",
               "approval_timeout": "PT2M",
               "mandate_digest": "sha256:9f2c…" } }
```

`reason` is REQUIRED, as is `mandate_digest` except for `invalid_mandate`; `rule_id` and
`approval_timeout` are included in the context when Section 4.1 provides for them.

Field mapping:

| AuthZEN | Input per Section 4 |
|---|---|
| `subject.id` | `agent.client_id`; together with `subject.properties.principal`, selects the mandate |
| `resource.id` | entity ID |
| `resource.type` | category |
| `resource.properties.area` | area |
| `action.name` | action |
| `context.time` | point in time |

The PDP does not use `resource.type`, `resource.properties.area` and `context.time` without
verification, but in accordance with Section 4 "Origin of inputs". If the PDP finds no mandate
for the agent and principal, the result is `deny` with `reason: invalid_mandate`.

- `outcome: allow` → `decision: true`
- `outcome: ask` → `decision: false`; the PEP MUST obtain a confirmation and MUST NOT execute
  the action unless the response is positive
- `outcome: deny` → `decision: false`

A PEP that does not know `ask` automatically treats the response as a denial. The
extension is thus backward-compatible and safe.

## 7. Transport in the OAuth flow (planned)

A mandate can be represented as an `authorization_details` object (RFC 9396) with
`type: "https://mandate-spec.org/mandate/v0"`, e.g. in
token introspection or when an agent proposes a desired mandate at sign-in.
In v0.1, the human always chooses the mandate; proposals by the agent are only pre-filled defaults.

## 8. Conformance and certification

`conformance/cases-v0.json` contains the cases: mandate + request + expected decision.
Paths to mandates are relative to the root directory of this repository. The collection grows
with every version; every bug found is first added as a case.

Fields of a case:

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | unique identifier |
| `mandate` / `mandate_inline` | one of them | path to the mandate, or the mandate inline in the case |
| `resource` | yes | `entity_id`, `category`, `area` of the resource |
| `action` | yes | requested action |
| `time` | yes | point in time per RFC 3339 |
| `timezone` | no | household time zone (IANA); if absent, the offset in `time` applies |
| `revoked` | no | `true`: status `revoked`; if the field is absent or `false`: status `active` |
| `expected` | yes | `allow`, `ask` or `deny` |
| `reason` | yes | expected reason code per Section 4.1 |
| `rule_id` | no | expected `rule_id` per Section 4.1; if the field is absent, it is not checked; `null` means: none |
| `approval_timeout` | no | expected `timeout` of the approval settings for `ask` |
| `why` | no | explanation for humans |

`conformance/invalid-v0.json` contains mandates that are invalid per Section 3.1 and
MUST be rejected (`mandate_inline`, or `mandate_raw` as a string if the
error cannot be represented as a JSON object, such as duplicate keys).

`conformance/digest-v0.json` contains, under `cases`, mandates (`mandate`, `mandate_inline` or
`mandate_raw`) with their expected digest `digest` (Section 3.2).

`conformance/audit-v0.json` contains, under `logs`, audit logs: `entries` (the entries in
file order), `expected` (`valid` or `invalid`), for `invalid` the expected position
`broken_at` (Section 9.4) and optionally `entry_digests` (the digest of each entry, for
debugging).

In addition to `cases` or `logs` respectively, every file has a `description`; every case has a
unique `id` and optionally `why`.

Two ways of testing:

1. **Library:** Implementations in Go can embed the reference evaluator from this
   repository or test their own evaluator against the cases.
2. **Black box:** The test tool `mandate-conformance` replays all cases against the
   AuthZEN endpoint of any implementation, independent of language and vendor.
   For this purpose, it loads the mandates via a test interface defined in Section 10
   (to follow with v0.2).

An implementation conforms to a version if it passes all cases of that version.
The test report is machine-readable and can be published. A formal
certification program with a logo will follow only once the specification is frozen.

## 9. Audit log

Every implementation maintains an audit log that shows **which agent did what, when, on the
basis of which configuration**. The format and the hash chain are fixed so that
audit logs of different implementations can be verified with the same tools.
Machine-readable: `schema/audit-v0.schema.json`.

### 9.1 Entries

Each entry is a JSON object with `type: "https://mandate-spec.org/audit/v0"` and:

| Field | Contents |
|---|---|
| `id` | UUIDv7 (RFC 9562) |
| `seq` | sequential number in the audit log, starting at 1, without gaps |
| `recorded_at` | point in time of the entry (RFC 3339) |
| `event` | event type (Section 9.2) |
| `principal` | principal |
| `prev` | digest of the previous entry (Section 9.4); `null` for the first entry |

Depending on the event, the following are added:

| Field | Contents |
|---|---|
| `actor` | who triggered a change: `kind` (`user`, `agent`, `system`) and `id` |
| `agent` | `client_id`, optionally `display_name` |
| `request` | input to the evaluation: `resource`, `action`, `time`, optionally `timezone` and `revoked` |
| `mandate` | `id`, `digest`, and for `mandate.updated` additionally `previous_digest` |
| `evaluation` | result per Section 4.1: `decision`, `reason`, `rule_id`, optionally `approval_timeout` |
| `approval` | outcome of an approval request: `outcome` (`approved`, `rejected`, `timeout`, `invalid_response`), `at`, `by` (who responded; required except for `timeout`) |
| `result` | `status`: `executed`, `denied` (with `denied_by`: `mandate`, `approval`, `rate_limit`, `emergency_stop`, `authentication`) or `failed` (with `error`, a code consisting of lowercase letters, digits and `_`); optionally `duration_ms` |
| `truncated` | `up_to_seq`, `last_digest` (Section 9.4) |

For `decision`, the following additionally applies:

- `executed` only with `evaluation` and `mandate`, and only if `evaluation.decision` is `allow`
  or `ask` with `approval.outcome: approved`;
- if `evaluation.decision` is `deny`, then `result` is `denied` with `denied_by: mandate`.

Entries **never** contain tokens, nonces, credentials or the content of a mandate.

### 9.2 Events

| `event` | Required | When |
|---|---|---|
| `decision` | yes | every request from an authenticated agent, even if it is rejected before evaluation (e.g. rate limit, emergency stop) |
| `mandate.created`, `mandate.updated`, `mandate.revoked` | yes | every change to a mandate, with old and new digest |
| `agent.registered`, `agent.revoked` | yes | admission and revocation of an agent |
| `emergency_stop.activated`, `emergency_stop.released` | yes | emergency stop, if the implementation has one |
| `log.truncated` | yes | before deleting old entries (Section 9.4) |
| `auth.rejected` | no | rejected sign-in or invalid token |

For `decision`, `evaluation` matches the result that the evaluation (Section 4)
returns for `request` and the version `mandate.digest`. This makes every decision
reproducible.

The rate limit (`limits`, enforced by the PEP) and the emergency stop are functions of the implementation
that this specification does not define further. If an implementation has them, it logs
denials with `denied_by: rate_limit` or `emergency_stop` respectively, and the emergency stop with the
`emergency_stop.*` events.

### 9.3 Retention

- Each mandate version is retained at least as long as entries that refer to its
  digest.
- How long entries are retained is determined by the implementation. Only the oldest entries
  MAY be deleted (Section 9.4).

### 9.4 Hash chain and verification

- Digest of an entry: `"sha256:" + hex(SHA-256(JCS(entry)))`, computed over the
  complete entry including `prev`.
- The `prev` of each entry is the digest of its predecessor; for the entry with `seq` 1,
  `prev` is `null`.
- Before the entries up to and including `seq` n are deleted, a `log.truncated` entry
  with `truncated: { up_to_seq: n, last_digest: <digest of entry n> }` is appended.
- Exchange format: JSON Lines (one entry per line, UTF-8, in ascending `seq` order).

An audit log is **valid** if, in file order:

1. every entry conforms to the schema;
2. the first entry either has `seq` 1, or a later `log.truncated` entry with
   `up_to_seq` = `seq` − 1 and `last_digest` = `prev` of the first entry is present;
3. every subsequent entry has the `seq` of its predecessor plus 1 and its `prev` is the
   predecessor's digest.

If an audit log is invalid, verification reports `broken_at`: the `seq` of the first entry in
file order that violates one of the conditions. The conditions are checked in the order
given: first the schema of all entries, then the start, then the chain.

Limitation: The hash chain reveals changes, gaps and reorderings **within** the
audit log. It does not detect removal of the most recent entries or modification of the last one.
For that, the end of the chain must be secured externally (signature or copy); this
will be addressed in a later version.

## 10. Test interface

To follow with v0.2.

## Changelog

### v0.1.0-alpha.1

Incompatible:
- `type` and schema `$id` moved to the neutral domain:
  `https://mandate-spec.org/mandate/v0`. Name of the specification: mandate-spec.
- New validity rules for mandates (Section 3.1): `format: date-time` is validated,
  no leap seconds, I-JSON, unique rule IDs, `time_window` with distinct start
  and end, actions matching the category, at most 256 KiB, `expires` after `valid_from`,
  approval timeout 10 s to 1 h, no control or format characters in displayed texts.
- `agent.client_id`: https URL or `<namespace>:<id>` instead of the product-specific
  prefix `hm-client:` (existing `hm-client:` IDs remain valid).
- Request: the entity ID is required and must match the pattern, as must the area; the status
  of the mandate is required (`active` or `revoked`).
- The schemas are normative.

Clarified (Section 4), each with new conformance cases:
- Pre-check: unknown category, action outside the vocabulary, invalid time specification
  or invalid mandate → `deny`.
- Validity period `valid_from ≤ t < expires`; revocation as an input to the evaluation.
- Local time via the household time zone; time window start inclusive, end
  exclusive; weekday of the point in time; behavior during daylight saving time transitions.
- `rule_id` and approval settings in the result (Section 4.1).
- `limits` are not part of the evaluation.
- Extensions without a known vocabulary → `deny`.
- Origin of inputs: category, area, time, time zone and status come from the PEP,
  never from the agent; comparison exact per character and case-sensitive.
- Time zones: only `UTC` or IANA identifiers of the form `Area/Location`; seconds are
  truncated.
- AuthZEN mapping of the fields (Section 6); the Home Assistant and Matter columns in the
  vocabulary are informative.
- Audit log: required fields per event, `executed` only after a permitting decision,
  `broken_at` also on schema violations (Section 9).

New:
- Digest of a mandate (Section 3.2), reason codes (Section 4.1), both
  required in the AuthZEN response context (Section 6).
- Audit log with a fixed format and hash chain (Section 9, `schema/audit-v0.schema.json`).
- Schema: time fields additionally with `pattern`.

Conformance cases: new fields `reason` (required), `timezone`, `revoked`, `rule_id`,
`approval_timeout`; new files `conformance/invalid-v0.json`, `conformance/digest-v0.json`,
`conformance/audit-v0.json`; test mandates under `conformance/mandates/`.
