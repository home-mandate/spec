# Mandats-Spezifikation v0 (Entwurf)

Status: **Arbeitsentwurf**, wird erst nach Einsatz in echten Haushalten eingefroren.
Lizenz dieses Dokuments: CC BY 4.0. Schema, Beispiele, Konformitätsfälle und Code: Apache 2.0.
Referenzimplementierung: Home-Mandate. Die Spezifikation bekommt vor der ersten
Veröffentlichung einen eigenen, produktneutralen Namen; mit ihm wandert auch der
`type`-Bezeichner auf eine neutrale Domain.

## 1. Ziel

Ein herstellerneutrales Format, das beschreibt, **was ein Software-Agent im Auftrag eines
Haushalts tun darf**, und eine Auswertungsregel, die in jeder Implementierung zum gleichen
Ergebnis führt. Die Spezifikation baut auf bestehenden Standards auf und definiert nur, was
fehlt:

| Zweck | Standard |
|---|---|
| Entscheidungs-Schnittstelle | OpenID AuthZEN Authorization API 1.0 |
| Transport des Mandats im OAuth-Fluss | Rich Authorization Requests (RFC 9396), `authorization_details` |
| Agenten-Identität | OAuth 2.1 Client-ID (bei MCP: Client ID Metadata Document) |
| Geräte-Vokabular | eigene Kategorien mit informativer Zuordnung zu Matter-Gerätetypen |

Neu definiert werden: das Mandats-Datenmodell, die dritte Entscheidung `ask`, Bedingungen,
Schutzklassen und die Auswertungsregel.

## 2. Begriffe

- **Vollmachtgeber (principal):** Haushalt oder Person, in deren Namen der Agent handelt.
- **Agent:** Software, die Aktionen anfragt, identifiziert über ihre OAuth-Client-ID.
- **Ressource:** ein einzelnes Gerät bzw. eine Entität.
- **Aktion:** was mit der Ressource geschehen soll, aus dem Vokabular ihrer Kategorie.
- **Entscheidung:** `allow` (sofort ausführen), `ask` (Mensch muss bestätigen), `deny` (ablehnen).

## 3. Datenmodell

Maschinenlesbar: `schema/mandate-v0.schema.json`. Kurzfassung:

```
Mandate
├── type          "https://home-mandate.com/spec/mandate/v0"
├── id            eindeutige ID
├── principal     "household:<id>" oder "person:<id>"
├── agent         { client_id, display_name }
├── rules[]       Regel
│   ├── id
│   ├── resource  Auswahl: entity_id | category | area | "*"  (mindestens eins)
│   ├── actions[] Aktionen aus dem Vokabular oder "*"
│   ├── decision  allow | ask | deny
│   ├── conditions? { time_window, weekdays }
│   ├── approval?   { timeout, approvers }   nur bei ask
│   └── allow_critical?  true, nötig für allow auf kritische Aktionen
├── default       immer "deny" in v0
├── approval      Standard für ask: { timeout, approvers }
├── limits        { max_actions_per_hour }
├── valid_from, expires?
└── created_by, created_at
```

## 4. Auswertungsregel

Eingabe: Mandat, Ressource (mit Kategorie und Bereich), Aktion, Zeitpunkt.

1. Ist das Mandat abgelaufen, noch nicht gültig oder widerrufen → `deny`.
2. Sammle alle Regeln, deren `resource` die Ressource trifft **und** deren `actions` die
   Aktion enthalten **und** deren `conditions` zum Zeitpunkt erfüllt sind.
   - `resource` trifft, wenn **alle** angegebenen Felder passen
     (z. B. `category: light` und `area: wohnzimmer` = Licht im Wohnzimmer).
   - `read` ist eine eigene Aktion. Schreibrechte schließen Leserechte nicht ein.
3. Keine Regel gefunden → `default` (`deny`).
4. Sonst gewinnt die **strengste** Entscheidung: `deny` vor `ask` vor `allow`.
5. Schutzklasse: Ist die Aktion **kritisch** (Abschnitt 5) und das Ergebnis `allow`, trägt
   aber nicht **jede** der passenden `allow`-Regeln `allow_critical: true` → Ergebnis wird `ask`.

Die Regel ist bewusst einfach: Wer etwas breit erlaubt und einzelnes verbietet, bekommt das
Verbot. Wer etwas breit auf `ask` stellt und einzelnes erlaubt, bekommt `ask`. Im Zweifel
gewinnt immer die sicherere Seite.

Bedingungen:
- `time_window`: `"HH:MM-HH:MM"` in Ortszeit des Haushalts; darf über Mitternacht gehen
  (`"22:00-06:00"`).
- `weekdays`: Liste aus `mon` … `sun`.

## 5. Vokabular v0

| Kategorie | Aktionen | Kritisch | HA-Zuordnung (Referenz) | Matter (informativ, zu verifizieren) |
|---|---|---|---|---|
| `light` | read, turn_on, turn_off, set | – | `light.*` | OnOffLight, DimmableLight |
| `switch` | read, turn_on, turn_off | – | `switch.*` | OnOffPlugInUnit |
| `climate` | read, set_temperature, set_mode | – | `climate.*` | Thermostat |
| `cover` | read, open, close, stop, set_position | – | `cover.*` (ohne Tor/Garage) | WindowCovering |
| `gate` | read, open, close | open | `cover.*` mit device_class `garage` oder `gate` | – |
| `lock` | read, lock, unlock, open | unlock, open | `lock.*` | DoorLock |
| `alarm` | read, arm, disarm | disarm | `alarm_control_panel.*` | – |
| `camera` | read, snapshot | snapshot | `camera.*` | Camera |
| `media` | read, turn_on, turn_off, play, pause, set_volume | – | `media_player.*` | – |
| `sensor` | read | – | `sensor.*`, `binary_sensor.*` | – |
| `scene` | read, activate | – | `scene.*` | – |
| `script` | read, run | run | `script.*` | – |
| `other` | read, set | set | alle übrigen Domains | – |

`script.run` und `other.set` sind kritisch, weil Skripte und unbekannte Entitäten beliebige
Folgen haben können, auch das Öffnen von Türen.

Erweiterungen für andere Plattformen erhalten eigene Namensräume, z. B.
`paperless:document` mit `read`, `tag`, `delete`.

## 6. AuthZEN-Abbildung

Der PEP fragt den PDP gemäß AuthZEN Authorization API 1.0 an:

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

AuthZEN kennt nur `true` oder `false`. Die dritte Entscheidung wird im Antwortkontext
übermittelt:

```json
{ "decision": false,
  "context": { "outcome": "ask", "rule_id": "r-locks", "approval_timeout": "PT2M" } }
```

- `outcome: allow` → `decision: true`
- `outcome: ask` → `decision: false`, PEP muss eine Bestätigung einholen und darf nur bei
  positiver Antwort ausführen
- `outcome: deny` → `decision: false`

Ein PEP, der `ask` nicht kennt, behandelt die Antwort automatisch als Ablehnung. Damit ist
die Erweiterung abwärtskompatibel und sicher.

## 7. Transport im OAuth-Fluss (vorgesehen)

Ein Mandat kann als `authorization_details`-Objekt (RFC 9396) mit
`type: "https://home-mandate.com/spec/mandate/v0"` dargestellt werden, z. B. in der
Token-Introspektion oder wenn ein Agent bei der Anmeldung ein gewünschtes Mandat vorschlägt.
In v0.1 wählt immer der Mensch das Mandat; Vorschläge des Agenten sind nur Vorbelegung.

## 8. Konformität und Zertifizierung

`conformance/cases-v0.json` enthält die Fälle: Mandat + Anfrage + erwartete Entscheidung.
Pfade zu Mandaten sind relativ zum Wurzelverzeichnis dieses Repositorys. Die Sammlung wächst
mit jeder Version; jeder gefundene Fehler wird zuerst als Fall ergänzt.

Zwei Prüfwege:

1. **Bibliothek:** Implementierungen in Go können die Referenz-Auswertung aus diesem
   Repository einbinden oder ihre eigene Auswertung gegen die Fälle testen.
2. **Black-Box:** Das Prüfwerkzeug `mandate-conformance` spielt alle Fälle gegen den
   AuthZEN-Endpunkt einer beliebigen Implementierung ab, unabhängig von Sprache und Hersteller.
   Es lädt dazu die Mandate über eine Test-Schnittstelle, die in Abschnitt 9 definiert wird
   (folgt mit v0.2).

Eine Implementierung ist konform zu einer Version, wenn sie alle Fälle dieser Version besteht.
Der Prüfbericht ist maschinenlesbar und kann veröffentlicht werden. Ein formales
Zertifizierungsprogramm mit Logo folgt erst, wenn die Spezifikation eingefroren ist.
