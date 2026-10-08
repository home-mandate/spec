# Profiles

Informative mappings from individual platforms to the vocabulary of the Home-Mandate
Specification (`vocabulary/v0.json`). A profile is a suggestion for implementers on that platform. It is
not part of the specification: conformance does not depend on it, and a platform without a
profile can be implemented just as well.

A profile describes

- which identifier of the platform serves as `entity_id` and which as `area`
  (SPEC-v0 section 3.4), preferably one that does not change when a device is renamed;
- how the platform's device types map to categories;
- how the platform's commands map to actions.

| Profile | Platform | Status |
|---|---|---|
| `home-assistant.md` | Home Assistant | used by one implementation |
| `matter.md` | Matter | draft, not verified against an implementation |

Profiles for other platforms (openHAB, KNX, Zigbee, HomeKit, …) are welcome; see
`CONTRIBUTING.md`.
