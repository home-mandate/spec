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
| Signatures | JSON Web Signature (RFC 7515) with EdDSA (RFC 8037) or ES256, keys as JWK (RFC 7517) |
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
├── issuer?, version?   only together, see Section 3.5
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
5. it is at most 262 144 bytes (256 KiB) in size. Lengths of strings in the schemas
   (`maxLength`, `minLength`) count Unicode code points, not bytes and not UTF-16 code units;
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

Implementations MUST reject invalid mandates when they are stored. If an invalid mandate is
nevertheless evaluated, the result MUST be `deny`.

Revocation of a mandate is not a field of the mandate but a state that the
implementation maintains and passes to the evaluation (Section 11.3).

Requirements in this document are written with the key words of BCP 14. Where a rule of
the data model, the evaluation or the audit log is stated as a fact ("the result is
`deny`", "seconds are truncated"), it is part of the definition and every conforming
implementation behaves that way.

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

### 3.5 Issuer and version

A mandate MAY name who issued it and which version it is:

- `issuer`: a URI with the same form as `agent.client_id` (Section 3.3), compared exactly.
- `version`: an integer of at least 1. Among the mandates with the same `id` from the same
  issuer, every change gets a higher version than every earlier one.

Both appear together or not at all. The digest (Section 3.2) says *which* version a
document is; it does not say which of two documents is newer. Without a version, an older
and more generous mandate with a valid digest cannot be told from the current one.

An implementation that stores a mandate and is offered a replacement with the same `id`
accepts it only if (**succession**):

1. the stored mandate has no `version`, or
2. the offered mandate has the same `issuer` and a `version` greater than the stored one.

A mandate without `version` therefore never replaces one that has a version, and an older
version is never accepted again (rollback). A mandate that leaves the implementation that
created it, signed per Section 7, MUST carry `issuer` and `version`.

## 4. Evaluation rule

Input: mandate, resource (entity ID, category, area, and whether the directory marks it as
critical), action, optionally parameters of the action (Section 4.5), point in time,
household time zone, status of the mandate (`active` or `revoked`). Which mandate is evaluated is determined by Section 4.3.

**Origin of inputs:** The PEP MUST determine the category, the area and the critical marking from its own resource
directory, the point in time from its own clock, the time zone from the household
configuration and the status from its own mandate management. It MUST NOT take any of these
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

`limits` are not part of the evaluation. The PEP enforces the rate limit (Section 11.2).

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
  implementation does not know result in `invalid_request`. Some time zone libraries match
  names without regard to case; an implementation that uses one MUST compare the spelling
  itself (`Europe/BERLIN` is not a name of the database). Names of this form that the
  database defines as links to another zone (such as `US/Eastern`) are permitted.
  The rules of a zone change with the release of the database; implementations SHOULD keep
  it current, and two implementations can differ for points in time that a newer release
  treats differently.
- If no time zone is given, the offset with which the point in time is expressed applies.
  A PEP SHOULD always pass the household time zone; without it, whoever chooses the offset
  of the point in time chooses the local time.
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
               "approval_timeout": "PT2M", "approvers": ["user-1"],
               "mandate_digest": "sha256:9f2c…" } }
```

`reason` is REQUIRED, as is `mandate_digest` unless Section 4.1 says it is absent; `rule_id` is
included when Section 4.1 provides for it. For `outcome: ask`, `approval_timeout` and
`approvers` (the approval settings per Section 4.1) are REQUIRED, so that a PEP can obtain
the confirmation without knowing the mandate.

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
- `outcome: ask` → `decision: false`; the PEP MUST obtain a confirmation per Section 11.1 and
  MUST NOT execute the action unless the response is positive
- `outcome: deny` → `decision: false`

A PEP that does not know `ask` automatically treats the response as a denial. The
extension is thus backward-compatible and safe.

`subject.type` MUST be `agent`; any other value is `deny` with `invalid_request`.

**Trust between PEP and PDP.** The PDP decides on the basis of the resource directory, the
clock, the household time zone and the mandate status. Whoever holds these is part of the
trusted side. If PEP and PDP are separate components, exactly one of them holds the
directory, and both MUST know which. The connection between them MUST be authenticated in
both directions and protected against modification; a PDP MUST NOT answer callers it has
not authenticated, and it MUST NOT be reachable by agents. A PDP that does not hold the
directory itself takes `resource.type`, `resource.properties` and `context.time` from the
authenticated PEP, and only from it.

## 7. Signed mandates and transport

As long as a mandate stays inside the implementation that stores and evaluates it, it
needs no signature. A mandate that travels (between an issuer and a PDP, between
implementations, or in an OAuth flow) is signed, so that the receiver can tell who
issued it and that it was not changed.

### 7.1 Signed mandate

A **signed mandate** is a JSON Web Signature in compact serialization (RFC 7515):

```
BASE64URL(header) "." BASE64URL(JCS(mandate)) "." BASE64URL(signature)
```

- The payload is the canonical form of the mandate (Section 3.2), byte for byte. A verifier
  MUST reject a payload that is not canonical; one mandate thus has exactly one payload.
- The mandate carries `issuer` and `version` (Section 3.5).
- The protected header has exactly two members: `alg` and `kid`. `alg` is `EdDSA` with
  Ed25519 (RFC 8037) or `ES256`. Every implementation that verifies signed mandates MUST
  support `EdDSA` and MAY support `ES256`. Any other algorithm (in particular `none`) and
  any other header member (such as `crit`, `b64`, `jwk`, `jku`, `x5c`) make the signed
  mandate invalid: a key is never taken from the signed object itself.
- `kid` is 1 to 64 characters from `A–Z a–z 0–9 . _ -` and names a key of the issuer.

A verifier accepts a signed mandate only if

1. it holds public keys that it trusts **for the issuer the mandate names**, and the
   signature verifies with the key `kid` among them;
2. the payload is canonical and a valid mandate (Section 3.1);
3. succession holds against what the verifier has stored (Section 3.5).

How a verifier comes to trust the keys of an issuer is outside this specification
(configuration, pairing, a JWK Set under the issuer's URL, …). Keys are exchanged as JWK or
JWK Set (RFC 7517): `{"kty":"OKP","crv":"Ed25519","x":…}` or
`{"kty":"EC","crv":"P-256","x":…,"y":…}`, each with a `kid`.

The algorithms are fixed per version of the specification. The prefix of a digest
(`sha256:`) and the `alg` of a signature name the algorithm, so that a later version can
add others without changing the format.

### 7.2 OAuth flow (informative)

A mandate can be represented as an `authorization_details` object (RFC 9396) with
`type: "https://mandate-spec.org/mandate/v0"`, e.g. in token introspection or when an agent
proposes a desired mandate at sign-in. The human always chooses the mandate; a proposal by
the agent is only a pre-filled default and is never evaluated. Where the object leaves the
party that issued it, the signed form of Section 7.1 is used.

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

`conformance/succession-v0.json` contains cases for Section 3.5: `stored` and `offered`
(two valid mandates) and `expected` (`accept` or `reject`).

`conformance/signed-v0.json` contains cases for Section 7.1: `jws` (the signed mandate),
`keys` (path to the JWK Set the verifier trusts), `issuer` (the issuer the keys are trusted
for), `expected` (`valid` or `invalid`) and, for `valid`, the `digest` of the mandate. The
keys in `conformance/keys/` are test keys whose private parts are public.

`conformance/digest-v0.json` contains, under `cases`, mandates (`mandate`, `mandate_inline` or
`mandate_raw`) with their expected digest `digest` (Section 3.2).

`conformance/audit-v0.json` contains, under `logs`, audit logs: `entries` (the entries in
file order), `expected` (`valid` or `invalid`), for `invalid` the expected position
`broken_at` (Section 9.4) and optionally `entry_digests` (the digest of each entry, for
debugging). Instead of `entries`, a log can be given as `jsonl`: the exchange format
(Section 9.4) as one string, for cases about line separators. With `keys` (path to a JWK
Set) the signatures of checkpoints are verified (Section 9.5), optionally against the
expected `log_id`; `anchored` is then the expected `seq` up to which a verified checkpoint
covers the log.

In addition to `cases` or `logs` respectively, every file has a `description`; every case has a
unique `id` and optionally `why`.

The format of each conformance file is itself described by a JSON Schema in
`conformance/schema/`, so that the files can be read and checked without the code in this
repository. `conformance/manifest.json` lists every machine-readable file of the
specification (schemas, examples, conformance files) with the SHA-256 of its bytes and, for
conformance files, the number of cases. A test report SHOULD name the manifest it was
produced with, so that it states exactly which cases were run.

### 8.1 Conformance classes

Not every implementation does everything. An evaluator library has no HTTP endpoint; a
verification tool for audit logs evaluates nothing. An implementation therefore conforms to
one or more **classes**, and it conforms to a class of a version if it passes all cases of
that class in that version.

| Class | What it does | Cases |
|---|---|---|
| `evaluator` | validates mandates, computes digests, evaluates requests (Sections 3 and 4) | `cases-v0.json`, `invalid-v0.json`, `digest-v0.json` |
| `selection` | selects the mandate among several (Section 4.3) | `selection-v0.json` |
| `signatures` | verifies signed mandates and succession (Sections 3.5 and 7) | `signed-v0.json`, `succession-v0.json` |
| `audit` | verifies the hash chain of audit logs and computes entry digests (Section 9.4) | logs in `audit-v0.json` without `keys` |
| `audit-anchored` | additionally verifies checkpoints (Section 9.5) | logs in `audit-v0.json` with `keys` |
| `pdp` | answers AuthZEN requests from its own mandate store and resource directory (Sections 4.3 and 6) | the cases of `cases-v0.json` and `selection-v0.json` whose mandates are valid, over HTTP |

`evaluator` is the basis: an implementation that claims any conformance to the
evaluation conforms to it. The obligations of the PEP (Section 11: approval, rate limit,
revocation) cannot be tested from outside in this version; an implementation states for
each item of Section 11 how it meets it.

A claim of conformance names the version (the tag of this repository), the classes and
the manifest (`conformance/manifest.json`, by its SHA-256). The report of the test tool
contains all three and can be published. A formal certification program will follow only
once the specification is frozen.

### 8.2 Ways of testing

1. **Library:** Implementations in Go can embed the reference code of this repository or
   test their own code against the cases directly.
2. **Test tool:** `mandate-conformance` (in `cmd/`) plays the cases against any
   implementation through the test interface of Section 10, independent of language and
   vendor, and writes a machine-readable report.

## 9. Audit log

Every implementation MUST maintain an audit log that shows **which agent did what, when, on the
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
| `result` | `status`: `executed`, `denied` (with `denied_by`: `mandate`, `approval`, `rate_limit`, `emergency_stop`, `authentication`) or `failed` (with `error`, a code consisting of lowercase letters, digits and `_`); `denied_by` only with `denied`, `error` only with `failed`; optionally `duration_ms`; optionally `count` (Section 11.2) |
| `truncated` | `up_to_seq`, `last_digest` (Section 9.4) |
| `checkpoint` | `log_id`, `signature` (Section 9.5) |

For `decision`, the following additionally applies:

- `executed` only with `evaluation` and `mandate`, and only if `evaluation.decision` is `allow`
  or `ask` with `approval.outcome: approved`;
- if `evaluation.decision` is `deny`, then `result` is `denied` with `denied_by: mandate`;
- `evaluation.reason` belongs to `evaluation.decision` as in the table of Section 4.1
  (`allow` only with `rule`, `ask` only with `rule` or `critical_demotion`);
- a denial with `denied_by: approval` carries the `approval` object if a request was
  answered or timed out. It has none if no request was made: no approver could be
  reached, or the agent already had too many requests waiting (Section 11.1).

A `log.truncated` entry has an `actor` of kind `user` or `system`; an agent never deletes
entries.

`actor.id`, `agent.display_name` and `approval.by` are displayed text; Section 3.1 item 8
applies to them, and an entry that violates it is invalid.

Entries MUST NOT contain tokens, nonces, credentials or the content of a mandate.

### 9.2 Events

| `event` | Required | When |
|---|---|---|
| `decision` | yes | every request from an authenticated agent, even if it is rejected before evaluation (e.g. rate limit, emergency stop) |
| `mandate.created`, `mandate.updated`, `mandate.revoked` | yes | every change to a mandate, with old and new digest |
| `agent.registered`, `agent.revoked` | yes | admission and revocation of an agent |
| `emergency_stop.activated`, `emergency_stop.released` | yes | emergency stop, if the implementation has one |
| `log.truncated` | yes | before deleting old entries (Section 9.4) |
| `log.checkpoint` | no | signed statement about the log so far (Section 9.5) |
| `auth.rejected` | no | rejected sign-in or invalid token |

For `decision`, `evaluation` matches the result that the evaluation (Section 4)
returns for `request` and the version `mandate.digest`. This makes every decision
reproducible.

The rate limit and the emergency stop are defined in Sections 11.2 and 11.3. Denials are
logged with `denied_by: rate_limit` or `emergency_stop` respectively, and the emergency stop
with the `emergency_stop.*` events.

### 9.3 Retention

- Each mandate version MUST be retained at least as long as entries that refer to its
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

An audit log without entries is valid. Verification reports the number of entries, because
an empty log proves nothing: a log that was emptied looks the same.

**What the chain proves, and what not.** The chain is neither keyed nor signed. It shows
that the entries of a log are consistent with one another: a change, a gap or a reordering
in the middle breaks it. It does **not** show that the log is the one the implementation
wrote. Whoever can write the log can

- remove the most recent entries or change the last one;
- recompute every digest from any entry onwards;
- replace the whole log with a new one that starts at `seq` 1;
- delete a prefix and append a matching `log.truncated` entry.

A valid chain is therefore evidence only together with an anchor outside the log:
a checkpoint (Section 9.5), or a copy of the log or of its latest digest kept where the
writer of the log cannot change it.

### 9.5 Checkpoints

A checkpoint anchors the log: a signed statement that the log with a certain identifier
had a certain entry at a certain position. The key that signs it MUST NOT be available to
whoever can merely write the log file; the public key is kept outside the log.

A checkpoint is an entry with `event: log.checkpoint` and

```
checkpoint: { "log_id": <UUID of the log>, "signature": <JWS> }
```

It covers the log up to and including its predecessor: the entry with `seq` − 1, whose
digest is the checkpoint's `prev`. A checkpoint is therefore never the first entry of a
log (`seq` ≥ 2).

- `log_id` is a UUID in lower case that the implementation chooses once per audit log.
  Every checkpoint of a log carries the same `log_id`; two logs never share one.
- `signature` is a JWS in compact serialization with **detached payload**
  (RFC 7515 appendix F, `header..signature`), with the header and algorithms of
  Section 7.1. The payload is the canonical form (RFC 8785) of

  ```json
  { "type": "https://mandate-spec.org/audit-checkpoint/v0",
    "log_id": <log_id>, "seq": <seq of the checkpoint entry − 1>, "digest": <prev of the checkpoint entry> }
  ```

Verification (Section 9.4) gains a fourth condition, checked after the chain:

4. all checkpoints carry the same `log_id`; and, if the verifier was given the public keys
   of the log, the `log_id` is the expected one (if the verifier expects one) and every
   checkpoint's signature verifies with one of these keys. `broken_at` is the `seq` of the
   first checkpoint that violates this.

A verifier that was given keys additionally reports up to which `seq` the log is
**anchored**: the position covered by the last checkpoint. Entries after it are consistent
but not anchored. Without keys, the signatures are not checked and nothing is anchored.

What a checkpoint adds: a log that was rewritten or replaced no longer matches the
checkpoints signed before, and nobody without the key can sign new ones. What it does not
add: it does not prevent the removal of entries after the last checkpoint, and a verifier
that does not know how far the log should reach cannot tell that the log and its last
checkpoints were removed together. Implementations SHOULD write a checkpoint at regular
intervals and before every `log.truncated`, and a party that relies on the log SHOULD keep
the `log_id` and the highest anchored `seq` it has seen.

## 10. Test interface

So that an implementation in any language and of any shape can be tested, the test
interface has two bindings. They are equivalent in what a passed case means; an
implementation offers the one that fits it. Neither is needed in operation.

### 10.1 Safety

The test interface lets its caller choose the mandates, the directory and the clock. An
implementation MUST NOT offer it in operation: not in a release build, or only after an
explicit start option that is off by default and that the implementation reports clearly.
State set through it MUST NOT mix with the household's real mandates and audit log.

### 10.2 Process binding

The implementation provides a program (a **harness**) that reads requests from its
standard input and writes responses to its standard output: one JSON object per line
(UTF-8, separated by line feed), one response for every request, in order. It needs no
network and no server. The harness ends when its input ends.

Mandates, audit entries and logs are passed as JSON **text inside a string**, so that they
arrive byte for byte (duplicate keys, number spellings and line separators are part of the
cases).

| `op` | Request members | Response members |
|---|---|---|
| `capabilities` | – | `name`, `version`, `ops` (the operations offered) |
| `validate` | `mandate` | `valid`; `digest` if valid |
| `evaluate` | `mandate`, `request` | `decision`, `reason`, `rule_id` if Section 4.1 provides one, `approval_timeout` and `approvers` for `ask`, `mandate_digest` unless absent per Section 4.1 |
| `select` | `mandates` (each `mandate`, optional `revoked`), `subject` (`client_id`, `principal`), `request` | as `evaluate`, plus `selected` (the `id` of the selected mandate) if one was selected |
| `succession` | `stored`, `offered` | `accept` |
| `verify_signed` | `jws`, `issuer`, `keys` (a JWK Set trusted for the issuer) | `valid`; `digest` if valid |
| `verify_audit` | `entries` (array of entry texts) or `jsonl` (the exchange format); optionally `keys` and `log_id` | `valid`, `entries` (their number); `broken_at` if invalid; `anchored` if valid and `keys` were given |
| `entry_digest` | `entry` | `digest` |

`request` is the input of the evaluation as the PEP determines it: `resource`
(`entity_id`, optionally `category`, `area`, `critical`), `action`, optionally `parameters`,
`time`, optionally `timezone` and `revoked`. A `time` that is no RFC 3339 timestamp or a
parameter that is no integer yields `deny` with `invalid_request`.

For an operation it does not offer, the harness answers `{"error": "unsupported"}`; the
cases of that operation then count as not passed for their class. Any other `error` is a
failed case. Every request can carry `id`, the identifier of the case, for diagnostics.

```
→ {"op":"evaluate","id":"c02","mandate":"{…}","request":{"resource":{"entity_id":"lock.haustuer","category":"lock","area":"flur"},"action":"unlock","time":"2026-10-12T19:00:00+02:00"}}
← {"decision":"ask","reason":"rule","rule_id":"r-locks","approval_timeout":"PT2M","approvers":["user-1"],"mandate_digest":"sha256:…"}
```

### 10.3 HTTP binding

For the class `pdp`. The implementation offers its AuthZEN endpoint (Section 6) and one
additional **control resource** at a URL of its choice. Before every case the test tool
sets the complete state with

```
PUT <control>
{ "mandates":  [ { "mandate": "<JSON text>", "revoked": false } ],
  "directory": [ { "entity_id": "…", "category": "…", "area": "…", "critical": false } ],
  "time": "2026-10-12T19:00:00+02:00", "timezone": "Europe/Berlin" }
```

which replaces everything set before: the stored mandates with their status, the resource
directory, the point in time the PDP uses as its clock, and the household time zone
(absent: the offset of `time` applies). The answer is a 2xx status. Then the tool sends the
request of the case to `POST <authzen>/access/v1/evaluation` with `subject` (type `agent`,
`id`, `properties.principal`), `action` (`name`, `properties` for parameters) and
`resource.id` only: category, area and the critical marking come from the directory. It
compares `decision` and, in the response context, `outcome`, `reason`, `rule_id` and
`approval_timeout`.

The tool sends the HTTP headers it was given (for example `Authorization`) with every
request; the control resource SHOULD require authentication even in a test build.

### 10.4 Test tool

`mandate-conformance -exec <command>` uses the process binding,
`mandate-conformance -authzen <url> -control <url>` the HTTP binding. The tool contains the
cases of its version. Its report (`-report`) is a JSON object with `spec`, `manifest` (the
SHA-256 of `conformance/manifest.json`), `binding`, `implementation`, per class the number
of cases passed, failed and skipped and whether the implementation conforms, and the list
of failed cases with what was expected and what was received. `cmd/mandate-harness` is the
harness of the reference code and an example for implementers.

## 11. Obligations of the PEP

The evaluation (Section 4) is a pure function. This section defines what an implementation
does around it. It states properties, not mechanisms: how a confirmation reaches a human,
which algorithm limits the rate and how the parts of an implementation talk to each other
is left open.

### 11.1 Approval

If the result of the evaluation is `ask`, the PEP obtains a confirmation from a human
before it executes the action.

1. **Who.** A confirmation counts only if it comes from one of the `approvers` of the
   approval settings (Section 4.1), authenticated by the implementation. One approver
   suffices. An approver that the user management no longer knows does not count. If no
   approver can be reached, the result is `deny`.
2. **What is confirmed.** A confirmation is bound to exactly one request: the agent, the
   resource, the action, its parameters and the `mandate_digest` of the evaluation. It
   MUST NOT be used for any other request, and the human MUST be shown what they confirm:
   the agent (`display_name` and `client_id`), the resource, the action and the parameters.
   Text supplied by the agent (a reason, for example) MUST be recognizable as such.
3. **Once.** A confirmation permits exactly one execution. A second use, a replay or a
   forged confirmation MUST be rejected; implementations use a value that cannot be
   guessed and accept it once.
4. **Independent of the agent.** The confirmation MUST reach the PEP on a path that the
   requesting agent does not control. An agent MUST NOT be able to deliver, relay or answer
   a confirmation, its own or another agent's. A voice assistant that asks "shall I
   unlock?" and reports the answer itself is not a confirmation.
5. **In time.** No answer within the `timeout` of the approval settings → `deny`. A
   rejection or an answer that is invalid (wrong person, wrong value, malformed) → `deny`.
   The execution follows the confirmation without delay; a confirmation that is older
   than `timeout` when the action would be executed has expired.
6. **Evaluated again.** After the confirmation and immediately before the execution, the
   PEP evaluates the request again. The action is executed only if the result is not
   `deny` and the `mandate_digest` is the one that was confirmed. A mandate that was
   revoked, changed or has expired in the meantime, a time window that has closed and an
   emergency stop all prevail over the confirmation.
7. **Limited.** The number of approval requests of one agent that wait for an answer at
   the same time MUST be limited (RECOMMENDED: 2). A request beyond the limit is `deny`
   without asking anyone. Requests that lead to `ask` count towards the rate limit
   (Section 11.2). Both protect the approvers from being worn down by repeated requests.

Every outcome is recorded in the audit log (Section 9.1) with `approval.outcome`, who
answered and, optionally, through which channel.

### 11.2 Rate limit

`limits.max_actions_per_hour` (N) bounds how often an agent can make the implementation
act or decide.

- In every period of 3600 seconds, at most N requests of the agent under the mandate
  reach the evaluation. Further requests are denied without evaluation
  (`denied_by: rate_limit`).
- Every request of the authenticated agent counts, whatever the action and whatever the
  result: `read`, requests that are denied and requests that lead to `ask`. Requests
  denied by the rate limit itself do not count.
- The bound is normative, the algorithm is not. A sliding window meets it; a token bucket
  that is full after an idle period does not, because it lets up to 2N requests pass
  within one hour.
- The count SHOULD survive a restart of the implementation; otherwise a crash resets the
  limit.
- A change of N applies to the next request.

So that an agent cannot fill the audit log with denials, consecutive requests of one agent
that the rate limit denies MAY be recorded as a single `decision` entry whose
`result.count` is the number of requests it stands for; `request` then describes the first
of them.

### 11.3 Revocation and emergency stop

- A revocation of a mandate or of an agent takes effect with the next evaluation: no
  request that is evaluated after the revocation was recorded is permitted. An
  implementation MUST NOT cache decisions beyond a request.
- Approval requests of the agent that are waiting end with `deny` when the mandate or the
  agent is revoked; Section 11.1 item 6 covers a confirmation that arrives at the same
  moment.
- An emergency stop is optional. If an implementation has one, then while it is active
  every request of every agent is denied without evaluation
  (`denied_by: emergency_stop`), waiting approval requests end with `deny`, and activating
  and releasing it are recorded (`emergency_stop.*`). Only a human can release it.

### 11.4 Clock and directory

The validity period, time windows and the audit log depend on the clock of the PEP, the
evaluation on its resource directory. An implementation SHOULD synchronize its clock and
SHOULD deny requests while it has reason to believe the clock is wrong (for example a time
before the newest entry of its audit log). Changes to the directory are covered by
Section 3.4.

## 12. Security considerations

### 12.1 What the specification protects

Assets: the physical security of the home (locks, gates, alarm), the privacy of its
inhabitants (cameras, presence, habits) and the integrity of the record of what agents did.

### 12.2 Attackers

| Attacker | What the specification does | What remains |
|---|---|---|
| **Agent that is malicious or was manipulated** (prompt injection through a website, an e-mail, a document) | The decision is made outside the agent. Default `deny`, most restrictive rule wins, critical actions need `allow_critical` or a human (Section 4). The agent supplies only the resource and the action; category, area, time and status come from the PEP. Rate limit and a limit on waiting approval requests (Section 11) | Everything the mandate allows, the agent can do. A mandate with a broad `allow` is a broad permission |
| **Agent that tries to obtain a confirmation** | The confirmation is bound to one request, used once, comes from a named approver on a path the agent does not control, and the request is evaluated again afterwards (Section 11.1) | A human who confirms without reading. The implementation MUST show what is confirmed; it cannot make the human read |
| **Agent that imitates a trusted name** | Displayed text carries no invisible or direction-changing characters (Section 3.1 item 8); identifiers are ASCII and compared exactly (Sections 3.3, 3.4) | Look-alike letters and names. Interfaces SHOULD show the `client_id` next to the `display_name` |
| **Member of the household who may change the resource directory** but not the mandates | Implementations MUST report mandates affected by a renamed resource or a changed area (Section 3.4); the critical marking can only add protection | Rules by `area` stop restricting when a resource leaves the area. Restrictions SHOULD name the category or the resource |
| **Attacker who can write the audit log** | Hash chain; checkpoints signed with a key the attacker does not have; verification reports how far the log is anchored (Sections 9.4, 9.5) | Entries after the last checkpoint. Without checkpoints, the chain proves consistency only |
| **Attacker who replays an old mandate** | `version` and succession (Section 3.5); signature of the issuer (Section 7) | Mandates without `version` are not ordered |
| **Attacker between PEP and PDP** | The connection MUST be authenticated in both directions; the PDP MUST NOT be reachable by agents (Section 6) | The specification does not define the mechanism |
| **Compromised PEP** | Nothing. The PEP executes; a PEP that ignores a `deny` cannot be stopped by a format | – |

### 12.3 Assumptions

The evaluation is only as trustworthy as its inputs. A conforming implementation relies on:

- **the resource directory**: it assigns category, area and the critical marking. A wrong
  category makes the wrong vocabulary and the wrong rules apply;
- **the clock**: validity periods and time windows depend on it (Section 11.4);
- **the user management**: it decides who an approver is and authenticates the person;
- **the approval channel**: it reaches the approver and nobody else can answer on it;
- **the authentication of the agent**: the specification assumes that the agent behind
  a `client_id` was authenticated; how is outside its scope;
- **the keys**: of issuers (Section 7) and of the audit log (Section 9.5).

### 12.4 Advice for implementers

- **Broad mandates.** `{"any": true}` with `"*"` and no `expires` is valid. Interfaces
  SHOULD warn before such a mandate is stored, SHOULD require a separate confirmation for
  every rule with `allow_critical`, and SHOULD suggest an `expires` for mandates that allow
  critical actions without approval.
- **Indirect effects.** A resource can act on others: a switch on a door opener, a scene
  that unlocks. The vocabulary cannot know this; the critical marking of the resource
  (Section 4, step 5) is the means for it.
- **Reading is not harmless.** `read` is never critical, but presence sensors, door
  contacts and cameras reveal who is at home. Mandates SHOULD allow `read` per category,
  not for `any`.
- **Parameters.** Only parameters of the vocabulary can be constrained. Whatever else a
  platform accepts with a command passes unchecked; a PEP SHOULD forward only what it has
  evaluated (Section 4.5).
- **Size and time.** Implementations SHOULD bound the size of inputs before parsing them
  (Section 3.1 item 5, nesting depth) and SHOULD verify signatures and schemas before any
  further processing.

## 13. Privacy considerations

The audit log records who caused which device to do what and when. It is a record of the
behavior of the people in a household and MUST be protected like the devices themselves.

- **Minimization.** Entries contain identifiers, not content: no tokens, no mandate text
  (Section 9.1), and no state that a `read` returned. Implementations SHOULD NOT add
  free text.
- **Retention.** How long entries are kept is up to the implementation and SHOULD be
  configurable by the household. The chain permits deletion from the oldest end
  (`log.truncated`); a checkpoint SHOULD precede it.
- **Persons.** `actor.id` and `approval.by` name people. Implementations SHOULD use
  identifiers from their user management rather than names, so that a person's name does
  not have to be removed from a chained log. Removing the data of a single person from the
  middle of a log is not possible without breaking the chain; this version offers no
  remedy other than retention limits.
- **Export.** An exported log leaves the protection of the implementation. Exports SHOULD
  be created only by a human and SHOULD be recorded.
- **Agents.** What an agent learns through `read` leaves the household with the agent.
  A mandate is also a decision about which data an agent may see.

## 14. Versions and compatibility

- **Identifier.** The `type` of a mandate (`https://mandate-spec.org/mandate/v0`) and of an
  audit entry name the major version. They are identifiers, not addresses that must
  resolve.
- **Draft.** Until v1.0, v0 can change incompatibly; every such change is listed in the
  Changelog together with what happens to mandates that were valid before. Releases of this
  repository are tagged (`v0.2.0`, …); an implementation states which tag it conforms to,
  and `conformance/manifest.json` identifies the exact cases.
- **Unknown members.** Mandates and audit entries have no extension points: a member
  that the schema does not define makes the document invalid. This is deliberate. An
  implementation that silently ignored a restriction it does not know would allow more
  than the household intended.
- **Consequence.** A newer mandate that uses a member an older implementation does not
  know is invalid there and denies everything. Implementations SHOULD therefore state
  which version they support before a mandate is transferred to them, and issuers SHOULD
  NOT use members the receiver does not support.
- **After v1.0.** A change that makes a valid v1 mandate invalid or changes the result of
  an evaluation requires a new `type`. Additions that an older implementation would have
  to understand to decide correctly require a new `type` as well.
- **Vocabulary and extensions** carry their own `id` and `version` (Section 5.1) and never
  change under the same pair.

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
- Audit log: `denied_by` only with `denied` and `error` only with `failed`;
  `evaluation.reason` must belong to `evaluation.decision`; `log.truncated` only by a user
  or the system (Section 9.1).
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
- Conformance classes (Section 8.1): `evaluator`, `selection`, `signatures`, `audit`,
  `audit-anchored`, `pdp`.
- Test interface (Section 10) with a process binding (JSON lines over standard input and
  output, no network) and an HTTP binding for PDPs; test tool `cmd/mandate-conformance`
  with a machine-readable report and `cmd/mandate-harness` as the harness of the
  reference code.
- Sections 12 to 14: security considerations with the attackers and assumptions, privacy
  considerations, versions and compatibility. More requirements are stated with the key
  words of BCP 14.
- Mandates can carry `issuer` and `version`; succession protects against rollback
  (Section 3.5, `conformance/succession-v0.json`).
- Signed mandates: compact JWS over the canonical form with EdDSA or ES256; Section 7 is
  normative now (`conformance/signed-v0.json`).
- Checkpoints anchor the audit log: event `log.checkpoint` with a `log_id` and a detached
  JWS over the position and digest of the log (Section 9.5); verification with keys reports
  up to which `seq` the log is anchored.
- Section 11, obligations of the PEP: approval (binding, single use, independence from the
  agent, re-evaluation, limits), rate limit (at most N requests in every period of 3600
  seconds, every request counts), revocation and emergency stop, clock.
- AuthZEN: `approvers` in the response context for `ask`; trust between PEP and PDP
  (Section 6).
- Audit log: `result.count` for combined rate limit denials; verification reports the
  number of entries; Section 9.4 states what the hash chain proves and what not.
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
  `evaluator.Request.Parameters`, package `ratelimit` (a limiter that meets the bound
  of Section 11.2), `audit.VerifyJSONLines` reads the log as a stream, package `jws`,
  `evaluator.Sign`, `evaluator.ParseSigned`, `evaluator.CheckSuccessor`,
  `audit.SignCheckpoint`, `audit.VerifyAnchored`.
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
