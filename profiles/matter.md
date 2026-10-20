# Profile: Matter (informative, draft)

Not verified against an implementation.

## Identifiers

| Home-Mandate | Matter | Note |
|---|---|---|
| `entity_id` | node ID and endpoint, e.g. `0x00000000000004D2/1` | Stable within a fabric. |
| areas | identifiers assigned by the implementation | Matter has no area that every controller shares. |

## Categories

| Category | Device types |
|---|---|
| `light` | On/Off Light, Dimmable Light, Color Temperature Light, Extended Color Light |
| `switch` | On/Off Plug-in Unit |
| `climate` | Thermostat |
| `cover` | Window Covering |
| `lock` | Door Lock |
| `camera` | Camera |
| `sensor` | sensor device types (Contact, Occupancy, Temperature, …) |
| `other` | all other device types |

## Parameters

### Climate modes

Writing the attribute SystemMode of the Thermostat cluster maps to the action `set_mode`
with the parameter `mode` (SPEC-v0 section 5). The permitted values of `mode` are the
values of SystemMode in lower case with underscores:

| SystemMode | Value | `mode` |
|---|---|---|
| Off | 0 | `off` |
| Auto | 1 | `auto` |
| Cool | 3 | `cool` |
| Heat | 4 | `heat` |
| EmergencyHeat | 5 | `emergency_heat` |
| Precooling | 6 | `precooling` |
| FanOnly | 7 | `fan_only` |
| Dry | 8 | `dry` |
| Sleep | 9 | `sleep` |

The parameter is the string, never the numeric value of the enumeration: `4` for `mode`
makes the request invalid (SPEC-v0 section 4.5). A value of SystemMode that a later
revision of Matter adds is not in the vocabulary and makes the request invalid.
