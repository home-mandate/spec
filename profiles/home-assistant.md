# Profile: Home Assistant (informative)

## Identifiers

| Home-Mandate | Home Assistant | Note |
|---|---|---|
| `entity_id` | entity ID (`light.living_room`) | Can be renamed by the user. An implementation MUST then tell the household which mandates are affected (SPEC-v0 section 3.4). The ID of the entity registry entry does not change, but not every entity has one. |
| areas | area ID of the entity, otherwise of its device, and `floor:` followed by the floor ID of that area if it has a floor | The floor is an additional area above the area, so a rule can name a room or a whole floor. Changes when the entity is moved to another area or the area to another floor. Area and floor IDs come from separate registries and can be equal, so floor IDs are always prefixed with `floor:` (for example `floor:ground_floor`); a prefix only on collision would change a floor's ID when an area of the same name is added, and rules would silently stop matching. A floor ID longer than 58 characters does not fit the 64 characters of an area with its prefix; the implementation then shortens it in a stable way, for example by a hash suffix. |

## Categories

| Category | Entities |
|---|---|
| `light` | `light.*` |
| `switch` | `switch.*` |
| `climate` | `climate.*` |
| `cover` | `cover.*` except device class `garage` or `gate` |
| `gate` | `cover.*` with device class `garage` or `gate` |
| `lock` | `lock.*` |
| `alarm` | `alarm_control_panel.*` |
| `camera` | `camera.*` |
| `media` | `media_player.*` |
| `sensor` | `sensor.*`, `binary_sensor.*` |
| `scene` | `scene.*` |
| `script` | `script.*` |
| `other` | all other domains |

## What an entity can do

Home Assistant reports the features of an entity in its state: the attribute
`supported_features` (a bit mask per domain) and, for some actions, other attributes. An
implementation can tell from them that an entity cannot carry out an action (SPEC-v0
section 11.1 item 11), for example:

| Category | Action | Needs |
|---|---|---|
| `lock` | `open` | `LockEntityFeature.OPEN` |
| `cover` | `open`, `close`, `stop`, `set_position` | `CoverEntityFeature.OPEN`, `CLOSE`, `STOP`, `SET_POSITION` |
| `gate` | `open`, `close` | `CoverEntityFeature.OPEN`, `CLOSE` |
| `light` | `set` (brightness) | a color mode in `supported_color_modes` other than `onoff` |
| `climate` | `set_temperature` | `ClimateEntityFeature.TARGET_TEMPERATURE` |
| `climate` | `set_mode` | the mode among the entity's `hvac_modes` (see Climate modes) |
| `media` | `turn_on`, `turn_off`, `play`, `pause`, `set_volume` | `MediaPlayerEntityFeature.TURN_ON`, `TURN_OFF`, `PLAY`, `PAUSE`, `VOLUME_SET` |
| `alarm` | `arm` | the feature of the mode, for example `AlarmControlPanelEntityFeature.ARM_AWAY` |

An entity that reports no `supported_features` tells nothing; the implementation then
asks as before. Some integrations change the features of an entity while it runs, so the
current state counts, not one remembered from earlier.

## Parameters

### Climate modes

`climate.set_hvac_mode` maps to the action `set_mode` with the parameter `mode`
(SPEC-v0 section 5). The HVAC modes of Home Assistant map to the permitted values:

| Home Assistant `hvac_mode` | `mode` | Note |
|---|---|---|
| `off` | `off` | |
| `heat` | `heat` | |
| `cool` | `cool` | |
| `heat_cool` | `auto` | Heats or cools to stay within a target range: the meaning of Matter's `Auto`. |
| `auto` | `auto` | Ambiguous, see below. |
| `dry` | `dry` | |
| `fan_only` | `fan_only` | |

**Ambiguity.** Home Assistant has two modes where Matter has one: `heat_cool` (the device
keeps the temperature within a range by heating or cooling) and `auto` (the device decides
by itself, for example from a schedule or what it learned). Both map to `auto`, because
the vocabulary has no other value that fits, and a mode that maps to no value could not be
allowed at all. A rule that permits `auto` therefore permits both, and a rule cannot
permit one without the other. An implementation SHOULD show the household that `auto`
stands for both modes of Home Assistant.

The values `emergency_heat`, `precooling` and `sleep` have no HVAC mode in Home Assistant;
an implementation never derives them. Preset modes (`climate.set_preset_mode`, such as
`eco`, `away` or `sleep`) are not system modes and do not map to `mode`; this profile
does not map them to an action. The parameter is derived from the requested HVAC mode, and
exactly that mode is executed (SPEC-v0 section 4.5). An HVAC mode that a later version of
Home Assistant adds and that is not in the table makes the request invalid until the
profile maps it.
