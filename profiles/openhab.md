# Profile: openHAB (informative, draft)

Not verified against an implementation. Based on input from Rich Koshak (@rkoshak) in the openHAB
community forum.

openHAB has two layers: Things and their Channels talk to the devices, Items are the
normalization layer on top. An Item can be linked to zero or more Channels, and these links can
change. A gateway works with Items only.

## Identifiers

| Home-Mandate | openHAB | Note |
|---|---|---|
| `entity_id` | Item name (`GarageDoor_Opener`) | The name the user gives the Item (letters, digits, underscores). It is unique and serves as the Item's identifier; there is no separate ID. It cannot be renamed; a "renamed" Item is a new Item and the old one is deleted. An implementation MUST then tell the household which mandates are affected (SPEC-v0 section 3.4). Rules and scenes are not Items; see "Rules and scenes" below. |
| `area` | name of the Location Group the Item belongs to, directly or through its Equipment | The semantic model nests Locations (Home → Ground Floor → Garage). SPEC-v0 knows one area per resource: the innermost Location. See [spec#28](https://github.com/home-mandate/spec/issues/28) for every enclosing Location as an additional area. Location Groups are Items, so their names cannot be renamed either. |

The semantic model is optional. An agent that is to make sense of a home will usually need it,
and so does this profile: without it, Items cannot be told apart reliably (see "Categories").

## Categories

The category comes from two sources together. The **Equipment** the Item belongs to tells what
the device is; the **Item type** tells how it is commanded. The Point and Property tags of the
Item (e.g. `Control` and `Opening`) confirm which Item of an Equipment is meant. Example:

```
Home                      Location
  Ground Floor            Location
    Garage                Location        → area
      Garage Door         Equipment       → category gate
        Opener            Switch, Control, Opening   → open/close (critical: open)
        OpenLevel         Number, Measurement, OpeningLevel → read
```

| Category | Equipment (semantic tag) | Item types |
|---|---|---|
| `light` | `Lightbulb`, `LightStripe` | Switch, Dimmer, Color, Number:Temperature (color temperature) |
| `switch` | `PowerOutlet`, `WallSwitch` | Switch |
| `climate` | `HVAC`, `RadiatorControl` | Number:Temperature (Point `Setpoint`), String or Number (mode) |
| `cover` | `Blinds`, `Window` (motorized) | Rollershutter, Dimmer |
| `gate` | `GarageDoor`, `Gate` | Switch, Rollershutter |
| `lock` | `Lock` | Switch |
| `alarm` | `AlarmSystem` | Switch, String, Number (binding-specific) |
| `camera` | `Camera` | Image |
| `media` | `Screen`, `Television`, `Receiver`, `Speaker`, `Projector` | Player, Switch, Dimmer (volume) |
| `sensor` | any, for Items with a Point `Measurement` or `Status`; Contact Items | Number, Contact, String, DateTime |
| `scene` | rules tagged `Scene` | – |
| `script` | all other rules and scripts | – |
| `other` | everything else, in particular Items outside the semantic model | any |

A Switch Item says only that it takes ON and OFF; it can drive a lamp as well as a door opener.
An Item is therefore `switch` only if its Equipment says so. A Switch without Equipment belongs
to `other`, where setting it is critical. The tag names follow the semantic model of openHAB 4
and 5 and still need to be checked against the current list.

## Actions

| Action | openHAB command | Note |
|---|---|---|
| `read` (all categories) | state of the Item | |
| `light.turn_on`, `light.turn_off` | `ON`, `OFF` | Dimmer and Color Items accept them as well. |
| `light.set` (`brightness`) | percent (0–100) | Dimmer, Color. Color and color temperature have no action yet ([spec#29](https://github.com/home-mandate/spec/issues/29)). |
| `switch.turn_on`, `switch.turn_off` | `ON`, `OFF` | |
| `climate.set_temperature` | quantity on the setpoint Item | `temperature` in 0.01 °C, `temperature_f` in 0.01 °F, depending on the unit of the Item (SPEC-v0 section 4.5). |
| `climate.set_mode` | mode value | binding-specific |
| `cover.open`, `cover.close`, `cover.stop` | `UP`, `DOWN`, `STOP` | |
| `cover.set_position` (`position`) | percent | openHAB counts 0 % as fully open, the specification counts percent **open**: `position` = 100 − value. To be checked per binding; some invert it. |
| `gate.open`, `gate.close` | `ON`/`OFF` or `UP`/`DOWN` | Many garage door openers take a single pulse that opens or closes depending on the current state. Such a command should be treated as `gate.open` (critical), never as `close`. |
| `lock.lock`, `lock.unlock` | `ON`, `OFF` | Which of the two locks is binding-specific. |
| `alarm.arm`, `alarm.disarm` | binding-specific | |
| `camera.snapshot` | Image Item | |
| `media.play`, `media.pause` | `PLAY`, `PAUSE` | Player Item |
| `media.turn_on`, `media.turn_off` | `ON`, `OFF` | |
| `media.set_volume` (`volume`) | percent | |
| `scene.activate`, `script.run` | running the rule | |
| `other.set` | any command | critical |

A gateway sends commands only. It does not post state updates, which would make openHAB and
its rules believe something that did not happen.

## Rules and scenes

Rules (including scenes, which are rules tagged `Scene`) are not Items. Their `entity_id` is the
rule UID with a prefix that no Item name can have, e.g. `rule:<uid>`; Item names contain only
letters, digits and underscores.

## The gateway as the only path

The mandate decides only what reaches openHAB through the gateway (SPEC-v0 section 12.3,
[spec#26](https://github.com/home-mandate/spec/issues/26)). The agent therefore gets no openHAB
credential of its own, and the gateway itself offers none of the other write paths of openHAB:
state updates, running rules directly (`/rest/rules/{uid}/runnow`), Things, configuration,
WebSockets, voice interpreters and the administration APIs. With the role `user`, openHAB can
still send commands to every Item; the gateway's own user should be as restricted as openHAB
allows. Item-level permissions in openHAB core are in progress and would let the gateway's user
be limited to what the household's mandates could ever allow.
