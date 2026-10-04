<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# mandate-spec v0 (Draft)

Status: **Working draft**; it will be frozen only after deployment in real households.
License of this document: CC BY 4.0 (`LICENSE-docs`). Schema, examples, conformance cases and
code: Apache 2.0 (`LICENSE`).
Reference evaluator: the code in this repository. Changes are listed in the Changelog at the end.

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
| Device vocabulary | own categories (`vocabulary/v0.json`); informative mappings to platforms in `profiles/` |

Newly defined are: the mandate data model, the third decision `ask`, conditions,
protection classes and the evaluation rule.

## 2. Terminology

- **Principal:** the household or person on whose behalf the agent acts.
- **Agent:** software that requests actions, identified by its OAuth client ID.
- **Resource:** a single device or entity, named by an identifier from the resource
  directory of the implementation.
- **Resource directory:** what the implementation knows about the resources of the
  household: for each identifier its category and, optionally, its area.
- **Action:** what is to be done with the resource, taken from the vocabulary of its category.
- **Decision:** `allow` (execute immediately), `ask` (a human must confirm), `deny` (reject).

## 3. Data model

Machine-readable: `schema/mandate-v0.schema.json`. The schemas in `schema/` are normative;
this text and the schemas MUST agree, and any contradiction is an error in the
specification.

**Patterns.** A `pattern` in the schemas applies to the entire string: a string matches only
if the pattern matches from its first to its last character. In particular, a trailing line
feed is not ignored. Regular expression dialects differ (ECMA-262, RE2, PCRE and others), so
the schemas use only constructs that mean the same in all of them: literal ASCII characters,
explicit character classes and ranges, groups, alternation, quantifiers, and `^` and `$` as
the first and last character. They do not use `\s`, `\d`, `\w`, `\b`, a bare `.`, flags or
lookarounds. An implementation MAY use any regular expression engine or none, as long as it
accepts exactly the strings the patterns describe.

Summary:

```
Mandate
├── type          "https://mandate-spec.org/mandate/v0"
├── id            unique ID
├── principal     "household:<id>" or "person:<id>"
├── agent         { client_id, display_name }   client_id: see Section 3.3
├── rules[]       rule
│   ├── id
│   ├── resource  selector: entity_id | category | area (at least one) or any: true alone
│   │             entity_id and area are opaque identifiers, see Section 3.4
│   ├── actions[] actions from the vocabulary or "*"
│   ├── decision  allow | ask | deny
│   ├── conditions? { time_window, weekdays }
│   ├── constraints? { <parameter>: { min, max } }   only with allow, see Section 4.5
│   ├── approval?   { timeout, approvers }   only with ask
│   └── allow_critical?  true, required for allow on critical actions; not together with "*"
├── default       always "deny" in v0
├── approval      default for ask: { timeout, approvers }
├── limits        { max_actions_per_hour }
├── valid_from, expires?
└── created_by, created_at
```

### 3.1 Validity of a mandate

A mandate is valid if it conforms to the schema **and** additionally:

0. all fields with `format: date-time` are valid RFC 3339 timestamps with an offset
   (implementations MUST validate `format`, not merely treat it as an annotation), written
   with an upper-case `T` and either `Z` or a numeric offset. Not permitted are: leap seconds
   (`:60`), more than 9 fractional digits, the year `0000` and the offset `-00:00`.
   Timestamps are compared as points in time with nanosecond precision;
1. it is I-JSON as defined in RFC 7493: valid UTF-8, no lone surrogates (e.g. a
   standalone `\ud800`), no JSON object with a duplicate key, exactly one JSON value;
2. all rule `id`s within the mandate are distinct;
3. for every `time_window`, start and end are distinct;
4. every action of a rule is `"*"` or belongs to the vocabulary:
   - if the rule's `resource` names a category from Section 5, to that category's
     vocabulary (e.g. `unlock` with `category: light` is invalid);
   - if it names no category, to the vocabulary of at least one category from Section 5.
     A misspelled action (`unlokc`) therefore never yields a valid rule that silently
     matches nothing. Actions of an extension can only be used together with the
     extension category;
   - if it names an extension category, the actions are not checked: whether a mandate
     is valid MUST NOT depend on which extensions an implementation knows. Rules for an
     extension that the implementation does not know never match (Section 4);
5. it is at most 262 144 bytes (256 KiB) in size;
6. `expires`, if present, is later than `valid_from`;
7. every `approval.timeout` is between 10 seconds and 1 hour (both inclusive). A timeout
   has the form `PT[nH][nM][nS]` with at least one component, in this order, each `n` a
   decimal number of 1 to 5 digits (`PT2M`, `PT1M30S`, `PT1H`). Its value is the sum of the
   components. Different spellings of the same duration are different mandates with
   different digests;
8. `agent.display_name`, `created_by` and all `approvers` are **displayed text**: they are
   shown to humans, for example in an approval request, and MUST NOT be able to mislead
   them. A displayed text
   - contains no code point listed under `forbidden` in
     `data/forbidden-codepoints-v0.json`. The list is normative and fixed; it was derived
     from Unicode 17.0.0 and contains the general categories Cc, Cf, Zl, Zp, Co and Cs
     (control and format characters, bidirectional controls, line and paragraph
     separators, private use, surrogates) and the property Default_Ignorable_Code_Point
     (invisible characters), except variation selectors and the two joiners;
   - does not begin or end with a code point listed under `white_space`;
   - contains the joiners U+200C (zero width non-joiner) and U+200D (zero width joiner)
     only between two other code points: not first, not last, and not directly after
     another joiner. Persian, Indic scripts and emoji sequences need them.

   Implementations MUST use the list, not the character tables of their runtime, so that
   validity does not change with a Unicode version. The rule cannot prevent look-alike
   letters from different scripts (homoglyphs); user interfaces SHOULD therefore show the
   `client_id` together with the `display_name`.

9. a rule with `allow_critical` lists its actions; it does not contain `"*"`. Whoever
   permits critical actions without an approval request names them, so that a later
   vocabulary cannot add to them silently.

10. `constraints` appear only in rules with `decision: allow` that list their actions
    (no `"*"`). For every constraint, `min` is not greater than `max`, and the named
    parameter is a parameter of **every** action of the rule: in the vocabulary of the
    rule's category or, if the rule names no category, of that action in at least one
    category from Section 5. Rules for an extension category are not checked. A
    constraint on a `deny` or `ask` rule would fail open, because a request without the
    parameter would not match the rule; therefore it is invalid.

All numbers in a mandate are integers whose magnitude is at most 2^53 − 1; the schema
permits nothing else.

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

Numbers are canonicalized by their value: `10`, `10.0` and `1e1` are the same number and
yield the same digest. Because mandates and audit log entries contain only integers, an
implementation needs no floating-point serialization for the canonical form: an integer
is written in decimal notation without fraction and exponent.

### 3.3 Agent identifier

`agent.client_id` identifies the agent. It is printable ASCII, at most 512 characters, and
has one of two forms:

- an **https URL** with a lower-case host, optionally a port, and a path; without userinfo
  (`user@`) and without a fragment (`#…`). This is the form of an OAuth Client ID Metadata
  Document URL;
- any **other URI**: a lower-case scheme, `:`, and 1 to 256 characters from
  `A–Z a–z 0–9 . _ ~ : / -`, for example an identifier assigned by the implementation
  (`<namespace>:<id>`), a DID (`did:web:agent.example`), a SPIFFE ID
  (`spiffe://example.org/agents/voice`) or a URN. The scheme `http` is not permitted.

Neither form contains a dot segment (`/./` or `/../`). Identifiers are compared exactly per
character, without normalization: two identifiers that differ in any character identify
different agents. How an implementation authenticates the agent behind an identifier is
outside this specification.

### 3.4 Resource and area identifiers

`entity_id` and `area` are **opaque identifiers**: 1 to 255 (`entity_id`) or 1 to 64 (`area`)
printable ASCII characters without space (U+0021 to U+007E). The specification gives them no
structure. Whatever names a platform uses can be used directly, for example
`light.living_room`, `Kitchen_Light`, `1/2/3`, `0x00000000000004D2/1`, a UUID or a URN; a
platform whose names contain other characters maps them, for example by percent-encoding.

Identifiers are compared exactly per character, without normalization and case-sensitive:
`Kitchen_Light` and `kitchen_light` are different resources.

Implementations SHOULD use identifiers that do not change when a human renames a device.
If the identifier of a resource changes, rules that name the old identifier no longer
match: an `allow` rule stops allowing, but a `deny` or `ask` rule stops restricting, and a
broader `allow` rule may then apply. The same holds when the area of a resource changes
or is removed. Implementations MUST therefore tell the household which mandates are
affected when an identifier or an area that a rule names changes or disappears, and
SHOULD express restrictions by category or by identifier, not by area alone.

`area` is the single grouping this version knows; what a platform calls room, zone,
floor or group can be mapped to it. `approvers` and `created_by` are identifiers from
the user management of the implementation and have no meaning outside it; a mandate
that moves to another implementation needs them replaced.

## 4. Evaluation rule

Input: mandate, resource (entity ID, category, area, and whether the directory marks it as
critical), action, optionally parameters of the action (Section 4.5), point in time,
household time zone, status of the mandate (`active` or `revoked`). Which mandate is evaluated is determined by Section 4.3.

**Origin of inputs:** The PEP determines the category, the area and the critical marking from its own resource
directory, the point in time from its own clock, the time zone from the household
configuration and the status from its own mandate management. It takes none of these
from the agent; only the requested resource and action originate from the agent.

The PEP MUST resolve the resource the agent names to the identifier under which its
directory knows it, and pass that identifier to the evaluation. Because identifiers are
compared exactly (Section 3.4), passing the agent's spelling unchanged would let a
different spelling of the same device slip past a rule. A resource the directory does not
contain has no category; the result is `deny` with `unknown_resource`.

0. Pre-check, each case → `deny`:
   - the mandate is invalid (Section 3.1);
   - the request is invalid: the entity ID is missing or does not match the pattern of
     `entity_id` in the schema, a given area does not match the pattern of `area`,
     a parameter is not an integer of magnitude at most 2^53 − 1, the point in time or the time zone is invalid or unknown, or the
     status is neither `active` nor `revoked`;
   - the category is missing: the resource is not in the directory of the PEP;
   - the category is neither listed in Section 5 nor an extension whose vocabulary
     the implementation knows;
   - the action does not belong to the vocabulary of the resource's category.
1. If the mandate is revoked, not yet valid or expired → `deny`.
   It is valid for points in time `t` with `valid_from ≤ t < expires` (without `expires`:
   `valid_from ≤ t`). Points in time are compared, not clock times.
2. Collect all rules whose `resource` matches the resource **and** whose `actions` contain the
   action **and** whose `conditions` are satisfied at the point in time **and** whose
   `constraints` are satisfied by the parameters (Section 4.5).
   - `resource` matches if **all** specified fields match
     (e.g. `category: light` and `area: wohnzimmer` = lights in the living room).
     `any: true` matches every resource. Comparison is exact per character, case-sensitive
     and without normalization.
   - `"*"` in `actions` contains every action, including critical ones.
   - `read` is an action in its own right. Write permissions do not include read permissions.
3. No rule found → `default` (`deny`).
4. Otherwise the **most restrictive** decision wins: `deny` over `ask` over `allow`.
5. Protection class: If the action is **critical** and the result is `allow`, but
   not **every** one of the matching `allow` rules carries `allow_critical: true` → the result becomes `ask`.
   For non-critical actions, `allow_critical` has no effect. An action is critical if
   - the vocabulary marks it as critical (Section 5), or
   - the resource directory marks the **resource** as critical and the action is not `read`.

   The marking of a resource lets a household protect what the vocabulary cannot know: a
   switch that drives a door opener, a ground-floor window, a heater. It can only add
   protection. An implementation SHOULD let the household mark resources as critical.

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
  | `no_mandate` | deny | no mandate for the agent and the principal (Section 4.3) |
  | `ambiguous_mandate` | deny | several mandates for the agent and the principal (Section 4.3) |
  | `invalid_mandate` | deny | mandate invalid (Section 3.1) |
  | `invalid_request` | deny | request invalid (step 0, second item) |
  | `unknown_resource` | deny | resource not in the directory of the PEP (no category) |
  | `unknown_category` | deny | category neither in Section 5 nor a known extension |
  | `unknown_action` | deny | action not in the category's vocabulary |
  | `revoked` | deny | mandate revoked |
  | `not_yet_valid` | deny | point in time before `valid_from` |
  | `expired` | deny | point in time at or after `expires` |
  | `no_match` | deny | no rule matches, `default` |
  | `critical_demotion` | ask | `allow` became `ask` per step 5 |
  | `rule` | allow, ask, deny | decision of a rule per step 4 |

- **`mandate_digest`:** digest of the evaluated mandate (Section 3.2); absent for
  `no_mandate`, `ambiguous_mandate` and `invalid_mandate`.
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
  Other names (including `Local`, `localtime`, `GMT` or abbreviations such as `CET`) and names that the
  implementation does not know result in `invalid_request`. Names of this form that the
  database defines as links to another zone (such as `US/Eastern`) are permitted.
  The rules of a zone change with the release of the database; implementations SHOULD keep
  it current, and two implementations can differ for points in time that a newer release
  treats differently.
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

### 4.3 Selection of the mandate

An implementation can store several mandates. Which one is evaluated for a request is
determined by the agent (`agent.client_id`) and the principal of the request, both compared
exactly. `household:x` and `person:x` are different principals; nothing is inherited from
one to the other. The PEP determines the principal; it does not take it from the agent.

1. Candidates are the stored mandates of the agent and the principal that are not revoked.
   A stored document that is not a valid mandate (Section 3.1) is a candidate as well.
2. No candidate → `deny` with `no_mandate`.
3. Of the candidates, those are *current* that are valid at the point in time
   (`valid_from ≤ t < expires`); an invalid document always counts as current.
   - exactly one current candidate → it is evaluated (Section 4);
   - several current candidates → `deny` with `ambiguous_mandate`. No mandate wins, and
     mandates are never combined;
   - no current candidate: if there is exactly one candidate, it is evaluated and yields
     `not_yet_valid` or `expired`; otherwise `deny` with `no_mandate`.

An agent can therefore have mandates that follow one another in time, but never two at
the same time. Implementations SHOULD refuse to store a mandate whose validity period
overlaps with another mandate of the same agent and principal that is not revoked.

### 4.4 Requests for several resources

The evaluation always concerns exactly one resource and one action. If an agent addresses
several resources at once (an area, a group, a list), the PEP resolves them with its
directory and evaluates each resource separately. Unless the PEP documents otherwise, the
request is executed only if every single evaluation permits it: one `deny` denies the whole
request, and one `ask` requires a confirmation that names all resources concerned.

A resource whose activation acts on other resources (a scene, a script, a group that the
platform executes itself) is evaluated as the resource it is; this is why `scene.activate`
and `script.run` are critical.

### 4.5 Parameters and constraints

Some actions carry a value: a temperature, a position, a volume. The vocabulary names
these **parameters** per action, with the unit in which they are expressed (Section 5).
Parameters are integers; the units are chosen fine enough that no fraction is needed
(a temperature is given in hundredths of a degree Celsius, 21.5 °C is `2150`).

The PEP derives the parameters from the request of the agent and converts them to the
unit of the vocabulary. It MUST execute exactly the values that were evaluated: whatever
it sends to the platform MUST NOT set a constrained quantity to another value, by rounding
or through a second, platform-specific parameter for the same quantity. A value that
cannot be expressed as an integer in the unit makes the request invalid.

A rule with `constraints` matches only if the request carries **every** named parameter
and each value `v` satisfies `min ≤ v ≤ max`; a limit that is not given does not restrict.
A request without the parameter does not match the rule. Parameters that no constraint
names do not influence the evaluation.

```json
{ "id": "r-heating", "resource": { "category": "climate" }, "actions": ["set_temperature"],
  "decision": "allow", "constraints": { "temperature": { "min": 1600, "max": 2300 } } }
```

Constraints narrow an `allow`. Whoever wants a confirmation for values outside the limits
adds an `ask` rule for the same action without constraints; `ask` then wins inside the
limits as well, so the usual form is: `allow` with constraints, and nothing else, which
denies everything outside.

## 5. Vocabulary v0

Machine-readable and normative: `vocabulary/v0.json` (format:
`schema/vocabulary-v0.schema.json`). The table shows its content.

| Category | Actions | Critical |
|---|---|---|
| `light` | read, turn_on, turn_off, set | – |
| `switch` | read, turn_on, turn_off | – |
| `climate` | read, set_temperature, set_mode | – |
| `cover` | read, open, close, stop, set_position | – |
| `gate` | read, open, close | open |
| `lock` | read, lock, unlock, open | unlock, open |
| `alarm` | read, arm, disarm | disarm |
| `camera` | read, snapshot | snapshot |
| `media` | read, turn_on, turn_off, play, pause, set_volume | – |
| `sensor` | read | – |
| `scene` | read, activate | activate |
| `script` | read, run | run |
| `other` | read, set | set |

Parameters (Section 4.5):

| Action | Parameter | Unit | Range |
|---|---|---|---|
| `light.set` | `brightness` | percent | 0 to 100 |
| `climate.set_temperature` | `temperature` | 0.01 degree Celsius | – |
| `cover.set_position` | `position` | percent open | 0 to 100 |
| `media.set_volume` | `volume` | percent | 0 to 100 |

`scene.activate`, `script.run` and `other.set` are critical because scenes, scripts and
unknown entities can have arbitrary consequences, including opening doors. What else is
critical in a particular household (a switch on a door opener, a ground-floor window) the
household marks in the resource directory (Section 4, step 5).

How an implementation assigns its resources to categories is its own matter and part of
its resource directory. A resource that fits no other category belongs to `other`.
`profiles/` contains informative mappings for individual platforms; they are not part of
the specification, and a platform without a profile is not at a disadvantage.

### 5.1 Extensions

Extensions for other kinds of resources receive their own namespaces, e.g.
`paperless:document` with `read`, `tag`, `delete`. An extension defines its vocabulary and
its critical actions in a file of the same format as `vocabulary/v0.json`, with its own
`id` and `version`; a vocabulary never changes under the same `id` and `version`. If an
implementation does not know the vocabulary of an extension, every request for a resource
of that category is `deny`. A registry of extensions does not exist yet.

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

`reason` is REQUIRED, as is `mandate_digest` unless Section 4.1 says it is absent; `rule_id` and
`approval_timeout` are included in the context when Section 4.1 provides for them.

Field mapping:

| AuthZEN | Input per Section 4 |
|---|---|
| `subject.id` | `agent.client_id`; together with `subject.properties.principal`, selects the mandate |
| `resource.id` | entity ID |
| `resource.type` | category |
| `resource.properties.area` | area |
| `action.name` | action |
| `action.properties` | parameters (Section 4.5): an object of parameter names and integers |
| `context.time` | point in time |

The PDP does not use `resource.type`, `resource.properties.area` and `context.time` without
verification, but in accordance with Section 4 "Origin of inputs"; the critical marking of a
resource likewise comes from the directory, never from the request. The mandate is selected
per Section 4.3; if there is none for the agent and principal, the result is `deny` with
`reason: no_mandate`.

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
| `resource` | yes | `entity_id`, `category`, `area` of the resource as the PEP resolved it, and optionally `critical: true` if the directory marks it as critical; without `category` the directory does not contain it |
| `action` | yes | requested action |
| `parameters` | no | parameters of the action (Section 4.5); a value that is not an integer stands for a request the PEP cannot express, the expected result is then `invalid_request` |
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

`conformance/selection-v0.json` contains cases for Section 4.3: `mandates` (the stored
mandates, each as `mandate_inline` with an optional `revoked`), `subject` (`client_id` and
`principal` of the request), the request as in `cases-v0.json`, `selected` (the `id` of the
mandate that is evaluated, or `null`) and the expected `expected`, `reason` and optionally
`rule_id`.

`conformance/digest-v0.json` contains, under `cases`, mandates (`mandate`, `mandate_inline` or
`mandate_raw`) with their expected digest `digest` (Section 3.2).

`conformance/audit-v0.json` contains, under `logs`, audit logs: `entries` (the entries in
file order), `expected` (`valid` or `invalid`), for `invalid` the expected position
`broken_at` (Section 9.4) and optionally `entry_digests` (the digest of each entry, for
debugging). Instead of `entries`, a log can be given as `jsonl`: the exchange format
(Section 9.4) as one string, for cases about line separators.

In addition to `cases` or `logs` respectively, every file has a `description`; every case has a
unique `id` and optionally `why`.

The format of each conformance file is itself described by a JSON Schema in
`conformance/schema/`, so that the files can be read and checked without the code in this
repository. `conformance/manifest.json` lists every machine-readable file of the
specification (schemas, examples, conformance files) with the SHA-256 of its bytes and, for
conformance files, the number of cases. A test report SHOULD name the manifest it was
produced with, so that it states exactly which cases were run.

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
| `seq` | sequential number in the audit log, starting at 1, without gaps. Read by its value: `1`, `1.0` and `1e0` are the same number; writers SHOULD use the plain form |
| `recorded_at` | point in time of the entry (RFC 3339) |
| `event` | event type (Section 9.2) |
| `principal` | principal |
| `prev` | digest of the previous entry (Section 9.4); `null` for the first entry |

Depending on the event, the following are added:

| Field | Contents |
|---|---|
| `actor` | who triggered a change: `kind` (`user`, `agent`, `system`) and `id` |
| `agent` | `client_id`, optionally `display_name` |
| `request` | input to the evaluation: `resource` (`entity_id`, optionally `category`, `area` and `critical`), `action`, `time`, optionally `parameters`, `timezone` and `revoked` |
| `mandate` | `id`, `digest`, and for `mandate.updated` additionally `previous_digest` |
| `evaluation` | result per Section 4.1: `decision`, `reason`, `rule_id`, optionally `approval_timeout` |
| `approval` | outcome of an approval request: `outcome` (`approved`, `rejected`, `timeout`, `invalid_response`), `at`, `by` (who responded; required except for `timeout`), optionally `via` (the channel the answer came through, an implementation-defined lowercase code such as `push` or `ui`; only together with `by`) |
| `result` | `status`: `executed`, `denied` (with `denied_by`: `mandate`, `approval`, `rate_limit`, `emergency_stop`, `authentication`) or `failed` (with `error`, a code consisting of lowercase letters, digits and `_`); optionally `duration_ms` |
| `truncated` | `up_to_seq`, `last_digest` (Section 9.4) |

For `decision`, the following additionally applies:

- `executed` only with `evaluation` and `mandate`, and only if `evaluation.decision` is `allow`
  or `ask` with `approval.outcome: approved`;
- if `evaluation.decision` is `deny`, then `result` is `denied` with `denied_by: mandate`.

`actor.id`, `agent.display_name` and `approval.by` are displayed text; Section 3.1 item 8
applies to them, and an entry that violates it is invalid.

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
- Exchange format: JSON Lines, UTF-8, in ascending `seq` order. Lines are separated by
  U+000A (line feed) and by nothing else: readers MUST NOT split at any other character,
  such as U+2028 inside a string. Every line is exactly one entry; white space that JSON
  permits around a value, including a carriage return before the line feed, is ignored. A
  line feed after the last entry is optional. A byte order mark and empty lines are not
  permitted; such a line counts as an entry that violates the schema.

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

### Unreleased

Incompatible; mandates that were valid before can become invalid, and an invalid mandate
denies every request. Implementations SHOULD check their stored mandates before they update:
- `agent.client_id` (new Section 3.3): https URLs need a lower-case host and a path and
  must not contain userinfo, a fragment, white space or non-ASCII characters; no dot
  segments. Newly permitted: other URIs such as `did:…`, `spiffe://…`, `urn:…`.
  Identifiers of the form `<namespace>:<id>` remain valid.
- Timestamps: at most 9 fractional digits; the year `0000` and the offset `-00:00` are
  invalid (Section 3.1 item 0).
- `entity_id` and `area` are opaque identifiers (new Section 3.4): printable ASCII without
  space, up to 255 and 64 characters, compared exactly. Every identifier that was valid
  before remains valid. The evaluation no longer rejects a request because of the form of
  an identifier; the PEP MUST resolve the requested resource in its directory (Section 4).
- A resource without category is `deny` with the new reason code `unknown_resource`
  instead of `invalid_request` (Section 4.1).
- A rule without category may only use actions that some category of the vocabulary has
  (Section 3.1 item 4); before, such actions were not checked.
- `scene.activate` is critical (Section 5): an `allow` rule without `allow_critical` now
  yields `ask`.
- `allow_critical` together with `"*"` is invalid (Section 3.1 item 9).
- "No mandate for the agent and principal" is `deny` with the new reason code `no_mandate`
  instead of `invalid_mandate`; several mandates at the same time are `ambiguous_mandate`
  (Sections 4.1, 4.3 and 6).
- Displayed text (Section 3.1 item 8): fixed code point list
  `data/forbidden-codepoints-v0.json` instead of the Unicode categories of the runtime;
  additionally forbidden are private-use and invisible (default ignorable) characters and
  white space at the start or end; newly permitted are ZWNJ and ZWJ between other
  characters. The rule now also applies to `actor.id`, `agent.display_name` and
  `approval.by` in the audit log.

Clarified, each with new conformance cases:
- Patterns apply to the entire string and use only a portable subset of regular
  expressions (Section 3).
- `approval.timeout`: hours are permitted (`PT1H`); at most 5 digits per component
  (Section 3.1 item 7).
- Numbers are read by their value: digest of a mandate (Section 3.2) and `seq` in the audit
  log (Section 9.1).
- Time zones: links of the time zone database such as `US/Eastern` are permitted
  (Section 4.2).
- Exchange format of the audit log: line feed as the only separator, no byte order mark, no
  empty lines (Section 9.4). `conformance/audit-v0.json` has the new field `jsonl` for it.

New:
- Critical resources: the resource directory can mark a resource as critical; then every
  action except `read` is critical (Section 4, step 5). New optional input `critical` of
  the evaluation, in the conformance cases and in `request.resource` of the audit log.
- Parameters and constraints (Section 4.5, Section 3.1 item 10): an `allow` rule can limit
  integer parameters of an action (`temperature`, `position`, `volume`, `brightness`);
  the vocabulary names the parameters and their units. New optional input `parameters`
  of the evaluation, in the conformance cases, in `action.properties` of the AuthZEN
  request and in `request.parameters` of the audit log.
- Selection of the mandate (Section 4.3) with `conformance/selection-v0.json`; requests for
  several resources (Section 4.4).
- `vocabulary/v0.json`: the vocabulary of Section 5 as a normative file, with
  `schema/vocabulary-v0.schema.json`; the same format for extensions (Section 5.1).
- `profiles/`: informative mappings of platforms to the vocabulary. The Home Assistant and
  Matter columns left the table in Section 5.
- Conformance cases with identifiers in the style of several platforms
  (`conformance/mandates/identifiers.json`).
- Reference code: `displaytext.Check`, `evaluator.Approval.Duration`,
  `evaluator.SelectAndEvaluate`, `evaluator.Resource.Critical`,
  `evaluator.Request.Parameters`.
- `conformance/schema/`: JSON Schemas of the conformance files; `conformance/manifest.json`:
  all machine-readable files with SHA-256 and number of cases (Section 8).
- `LICENSE` (Apache 2.0), `LICENSE-docs` (CC BY 4.0), `SECURITY.md`, `CONTRIBUTING.md`.
- Audit log: optional `approval.via`, the channel an answer came through (Section 9.1),
  so that a log shows whether a person confirmed on a phone or in a user interface.
  Conformance cases `a11`–`a13` in `conformance/audit-v0.json`.
- Reference evaluator: `IsCritical` exposes the critical actions of the vocabulary
  (Section 5); anything outside the vocabulary counts as critical.

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
