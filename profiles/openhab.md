# Profile: openHAB (informative, draft)

Not verified against an implementation. Based on input from Rich Koshak (@rkoshak) in the openHAB
community forum and in the review of this profile.

openHAB has two layers: Things and their Channels talk to the devices, Items are the
normalization layer on top. An Item can be linked to zero or more Channels, and these links can
change. A gateway works with Items only. The Item type alone decides which commands and states
are valid (Switch, Dimmer, Rollershutter, …); the binding behind it does whatever that command
means for its device.

"Category" means something else in openHAB: there it selects the icon of an Item. In this
profile it always means the category of the vocabulary (`vocabulary/v0.json`).

## Identifiers

| Home-Mandate | openHAB | Note |
|---|---|---|
| `entity_id` | Item name (`GarageDoor_Opener`) | The name the user gives the Item (letters, digits, underscores). It is unique and serves as the Item's identifier; there is no separate ID. It cannot be renamed; a "renamed" Item is a new Item and the old one is deleted. An implementation MUST then tell the household which mandates are affected (SPEC-v0 section 3.4). Rules and scenes are not Items; see "Rules and scenes" below. |
| `area` | name of the Location Group the Item is a direct member of, or, for an Item of an Equipment, the Location Group the Equipment is a direct member of | Location Groups are Items, so their names cannot be renamed either. See "Areas" below. |

The semantic model is optional. An agent that is to make sense of a home will usually need it,
and so does this profile: without it, Items cannot be told apart reliably (see "Categories").

## Areas

Locations are Group Items and nest: Garage is a member of Ground Floor, Ground Floor a member of
Home. In the semantic model an Item, an Equipment or a Location is a direct member of at most
one Location, so a resource is in several Locations only through this chain. SPEC-v0 knows one
area per resource: the Location directly above the Item or its Equipment. Once
[spec#28](https://github.com/home-mandate/spec/issues/28) is in, the areas of a resource are the
whole chain (Garage, Ground Floor, Home).

Groups outside the semantic model (e.g. `AllLights`) are not areas. An Item can be a member of
any number of them; they say nothing about where a device is.

## Categories

The category comes from two sources together. The **Equipment** the Item belongs to tells what
the device is; the **Item type** tells how it is commanded. The Point and Property tags of the
Item (e.g. `Control` and `Opening`) tell which Item of an Equipment is meant. Example:

```
Home                      Location
  Ground Floor            Location
    Garage                Location        → area
      Garage Door         Equipment       → category gate
        Opener            Switch, Control, Opening   → open/close (critical: open)
        OpenLevel         Number, Measurement, Opening → read
```

Semantic tags form a hierarchy, and users can add their own tags below the standard ones. The
category is therefore taken from the **nearest standard ancestor** of the Equipment tag, not from
a fixed list of tag names. openHAB returns the tags and their parents through the REST API (and
shows them under Developer Tools → Semantic Tags). A custom tag that does not descend from one of
the tags below, or a separate tag hierarchy of the user's own, leads to `other`.

| Category | Equipment tag or ancestor (openHAB 5) | Item types |
|---|---|---|
| `light` | `LightSource` (`Lightbulb`, `Lamp`, `LightStrip`, …) | Switch, Dimmer, Color |
| `switch` | `PowerOutlet`, `WallSwitch` | Switch |
| `climate` | `HVAC` (`Thermostat`, `RadiatorControl`, `AirConditioner`, …), for Items with Property `Temperature` or `Mode` | Number:Temperature (Point `Setpoint`), String or Number (mode) |
| `cover` | `WindowCovering` (`Blinds`, `Drapes`) | Rollershutter |
| `gate` | `Door` (`GarageDoor`, `Gate`, `FrontDoor`, …), for Items with Point `Control` and Property `Opening` | Switch, Rollershutter |
| `lock` | `Lock` | Switch |
| `alarm` | `AlarmSystem` | Switch, String, Number |
| `camera` | `Camera` | Image |
| `media` | `AudioVisual` (`Television`, `Speaker`, `Receiver`, `MediaPlayer`, …) | Player, Switch, Dimmer (volume) |
| `sensor` | any, for Items with a Point `Measurement` or `Status`; Contact Items | Number, Contact, String, DateTime |
| `scene` | rules tagged `Scene` | – |
| `script` | all other rules and scripts | – |
| `other` | everything else, in particular Items outside the semantic model and Group Items | any |

A Switch Item says only that it takes ON and OFF; it can drive a lamp as well as a door opener.
An Item is therefore `switch` only if its Equipment says so. A Switch without Equipment belongs
to `other`, where setting it is critical.

## Actions

A command is not a state: an Item never takes the state `INCREASE`, it takes the value the
binding made of it. A constraint (SPEC-v0 section 4.5) can only be checked against a value that
is known before the command is sent. A gateway therefore sends **absolute commands only** and
offers no relative ones (`INCREASE`, `DECREASE`, `TOGGLE`, `MOVE`, `NEXT`, …).

| Action | openHAB command | Note |
|---|---|---|
| `read` (all categories) | state of the Item | |
| `light.turn_on`, `light.turn_off` | `ON`, `OFF` | Dimmer and Color Items accept them as well. |
| `light.set` (`brightness`) | percent (0–100) | Dimmer, Color. Color and color temperature have no action yet ([spec#29](https://github.com/home-mandate/spec/issues/29)). |
| `switch.turn_on`, `switch.turn_off` | `ON`, `OFF` | |
| `climate.set_temperature` | quantity on the setpoint Item | `temperature` in 0.01 °C, `temperature_f` in 0.01 °F, depending on the unit of the Item (SPEC-v0 section 4.5). |
| `climate.set_mode` | one of the options of the Item's command description | |
| `cover.open`, `cover.close`, `cover.stop` | `UP`, `DOWN`, `STOP` | |
| `cover.set_position` (`position`) | percent | Whether 100 % means open or closed differs between bindings and integrations. A gateway offers this action only for an Item whose direction the household has stated, and converts to percent **open**. |
| `gate.open`, `gate.close` | `ON`/`OFF` or `UP`/`DOWN` | |
| `lock.lock`, `lock.unlock` | `ON`, `OFF` | Which of the two means locked is to be confirmed. |
| `alarm.arm`, `alarm.disarm` | `ON`/`OFF`, or an option of the command description | |
| `camera.snapshot` | Image Item | |
| `media.play`, `media.pause` | `PLAY`, `PAUSE` | Player Item |
| `media.turn_on`, `media.turn_off` | `ON`, `OFF` | |
| `media.set_volume` (`volume`) | percent | |
| `scene.activate`, `script.run` | running the rule | |
| `other.set` | any absolute command | critical |

A gateway sends commands only. It does not post state updates, which would make openHAB and
its rules believe something that did not happen.

## Group Items

A command to a Group Item is forwarded by openHAB to all its members. A gateway resolves a Group
into its members and evaluates and commands each of them (SPEC-v0 section 4.4); it does not send
the command to the Group. A Group Item addressed as itself belongs to `other`.

## Rules and scenes

Rules (including scenes, which are rules tagged `Scene`) are not Items. Their `entity_id` is the
rule UID with a prefix that no Item name can have, e.g. `rule:<uid>`; Item names contain only
letters, digits and underscores.

Running a rule allows whatever the rule does, including running other rules. This is why
`scene.activate` and `script.run` are critical (SPEC-v0 section 4.4).

Rules can also be triggered by a command to an Item, or by a change or update of its state. A
command the mandate allows can therefore start a rule the household would not allow the agent to
run. openHAB returns the triggers of every rule through the REST API, so a gateway should show the
household which rules react to an Item and suggest marking such an Item as critical (SPEC-v0
section 4, step 5). Button presses are usually linked from a Channel to a rule directly, without
an Item; an agent cannot cause them.

## The gateway as the only path

The mandate decides only what reaches openHAB through the gateway (SPEC-v0 section 12.3,
[spec#26](https://github.com/home-mandate/spec/issues/26)). The agent therefore gets no openHAB
credential of its own, and the gateway itself offers none of the other write paths of openHAB:
state updates, running rules directly (`/rest/rules/{uid}/runnow`), Things, configuration,
WebSockets, voice interpreters and the administration APIs. With the role `user`, openHAB can
still send commands to every Item; the gateway's own user should be as restricted as openHAB
allows. Item-level permissions in openHAB core are in progress and would let the gateway's user
be limited to what the household's mandates could ever allow.
