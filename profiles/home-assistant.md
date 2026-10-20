# Profile: Home Assistant (informative)

## Identifiers

| Home-Mandate | Home Assistant | Note |
|---|---|---|
| `entity_id` | entity ID (`light.living_room`) | Can be renamed by the user. An implementation MUST then tell the household which mandates are affected (SPEC-v0 section 3.4). The ID of the entity registry entry does not change, but not every entity has one. |
| areas | area ID of the entity, otherwise of its device, and `floor:` followed by the floor ID of that area if it has a floor | The floor is an additional area above the area, so a rule can name a room or a whole floor. Changes when the entity is moved to another area or the area to another floor. Area and floor IDs come from separate registries and can be equal, so floor IDs are always prefixed with `floor:` (for example `floor:ground_floor`); a prefix only on collision would change a floor's ID when an area of the same name is added, and rules would silently stop matching. |

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
