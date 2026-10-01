# mandate-spec v0 (Entwurf)

Status: **Arbeitsentwurf**, wird erst nach Einsatz in echten Haushalten eingefroren.
Lizenz dieses Dokuments: CC BY 4.0. Schema, Beispiele, Konformitätsfälle und Code: Apache 2.0.
Referenzimplementierung: Home-Mandate. Änderungen stehen im Änderungsprotokoll am Ende.

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
├── type          "https://mandate-spec.org/mandate/v0"
├── id            eindeutige ID
├── principal     "household:<id>" oder "person:<id>"
├── agent         { client_id, display_name }
├── rules[]       Regel
│   ├── id
│   ├── resource  Auswahl: entity_id | category | area (mindestens eins) oder allein any: true
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

### 3.1 Gültigkeit eines Mandats

Ein Mandat ist gültig, wenn es das Schema erfüllt **und** zusätzlich:

0. alle Felder mit `format: date-time` gültige Zeitpunkte nach RFC 3339 mit Offset sind
   (Implementierungen müssen `format` prüfen, nicht nur als Anmerkung behandeln);
1. kein JSON-Objekt darin einen Schlüssel doppelt enthält;
2. alle Regel-`id`s innerhalb des Mandats verschieden sind;
3. bei jedem `time_window` Beginn und Ende verschieden sind;
4. jede Regel, deren `resource` eine Kategorie aus Abschnitt 5 nennt, nur Aktionen aus deren
   Vokabular oder `"*"` enthält (z. B. ist `unlock` bei `category: light` ungültig).
   Nennt die Regel eine Erweiterungs-Kategorie, deren Vokabular die Implementierung nicht
   kennt, entfällt diese Prüfung; solche Regeln treffen bei der Auswertung nie (Abschnitt 4).

Implementierungen lehnen ungültige Mandate beim Speichern ab. Wird trotzdem ein ungültiges
Mandat ausgewertet, ist das Ergebnis immer `deny`.

Der Widerruf eines Mandats ist kein Feld des Mandats, sondern ein Zustand, den die
Implementierung führt und der Auswertung übergibt.

### 3.2 Fingerabdruck eines Mandats

Jede Fassung eines Mandats wird über ihren Fingerabdruck eindeutig bezeichnet:

```
digest = "sha256:" + hex(SHA-256(JCS(mandat)))
```

- `JCS` ist die kanonische JSON-Form nach RFC 8785: Schlüssel sortiert, keine Leerzeichen,
  festgelegte Schreibweise von Zeichenketten und Zahlen.
- Berechnet wird über das gültige Mandat (Abschnitt 3.1), nicht über die gespeicherten
  Bytes. Reihenfolge der Schlüssel und Leerraum ändern den Fingerabdruck daher nicht; jede
  inhaltliche Änderung ändert ihn.
- `hex` schreibt Kleinbuchstaben, 64 Zeichen.

Der Fingerabdruck verweist im Protokoll (Abschnitt 9) auf die Fassung, nach der entschieden
wurde, ohne den Inhalt des Mandats ins Protokoll zu schreiben.

## 4. Auswertungsregel

Eingabe: Mandat, Ressource (Entitäts-ID, Kategorie, Bereich), Aktion, Zeitpunkt,
Zeitzone des Haushalts, Widerrufsstatus.

0. Vorprüfung, jeweils → `deny`:
   - das Mandat ist ungültig (Abschnitt 3.1);
   - die Ressource hat keine Kategorie, oder die Kategorie steht weder in Abschnitt 5 noch
     ist sie eine Erweiterung, deren Vokabular die Implementierung kennt;
   - die Aktion gehört nicht zum Vokabular der Kategorie der Ressource;
   - Zeitpunkt oder Zeitzone sind ungültig oder unbekannt.
1. Ist das Mandat widerrufen, noch nicht gültig oder abgelaufen → `deny`.
   Gültig ist es für Zeitpunkte `t` mit `valid_from ≤ t < expires` (ohne `expires`:
   `valid_from ≤ t`). Verglichen werden Zeitpunkte, nicht Uhrzeiten.
2. Sammle alle Regeln, deren `resource` die Ressource trifft **und** deren `actions` die
   Aktion enthalten **und** deren `conditions` zum Zeitpunkt erfüllt sind.
   - `resource` trifft, wenn **alle** angegebenen Felder passen
     (z. B. `category: light` und `area: wohnzimmer` = Licht im Wohnzimmer).
     `any: true` trifft jede Ressource.
   - `"*"` in `actions` enthält jede Aktion, auch kritische.
   - `read` ist eine eigene Aktion. Schreibrechte schließen Leserechte nicht ein.
3. Keine Regel gefunden → `default` (`deny`).
4. Sonst gewinnt die **strengste** Entscheidung: `deny` vor `ask` vor `allow`.
5. Schutzklasse: Ist die Aktion **kritisch** (Abschnitt 5) und das Ergebnis `allow`, trägt
   aber nicht **jede** der passenden `allow`-Regeln `allow_critical: true` → Ergebnis wird `ask`.
   Bei nicht kritischen Aktionen hat `allow_critical` keine Wirkung.

Die Regel ist bewusst einfach: Wer etwas breit erlaubt und einzelnes verbietet, bekommt das
Verbot. Wer etwas breit auf `ask` stellt und einzelnes erlaubt, bekommt `ask`. Im Zweifel
gewinnt immer die sicherere Seite.

`limits` sind nicht Teil der Auswertung. Das Tempolimit setzt der PEP durch.

### 4.1 Ergebnis

Neben der Entscheidung liefert die Auswertung:

- **`reason`:** genau ein Begründungscode. Treffen mehrere Gründe zu, gilt der erste in
  dieser Reihenfolge:

  | Code | Entscheidung | Bedeutung |
  |---|---|---|
  | `invalid_mandate` | deny | Mandat ungültig (Abschnitt 3.1) |
  | `invalid_request` | deny | Ressource ohne Kategorie, Zeitpunkt oder Zeitzone ungültig oder unbekannt |
  | `unknown_category` | deny | Kategorie weder in Abschnitt 5 noch bekannte Erweiterung |
  | `unknown_action` | deny | Aktion nicht im Vokabular der Kategorie |
  | `revoked` | deny | Mandat widerrufen |
  | `not_yet_valid` | deny | Zeitpunkt vor `valid_from` |
  | `expired` | deny | Zeitpunkt ab `expires` |
  | `no_match` | deny | keine Regel trifft, `default` |
  | `critical_demotion` | ask | `allow` wurde nach Schritt 5 zu `ask` |
  | `rule` | allow, ask, deny | Entscheidung einer Regel nach Schritt 4 |

- **`mandate_digest`:** Fingerabdruck des ausgewerteten Mandats (Abschnitt 3.2); fehlt bei
  `invalid_mandate`.
- **`rule_id`:** die erste Regel in Dokumentreihenfolge, die die Endentscheidung trägt.
  Bei Schritt 5 ist das die erste passende `allow`-Regel ohne `allow_critical`.
  Bei Vorprüfung, Schritt 1 und Schritt 3 gibt es keine `rule_id`.
- **Freigabe-Einstellung** (nur bei `ask`): `approval` der ersten passenden `ask`-Regel in
  Dokumentreihenfolge, die ein eigenes `approval` hat, sonst das `approval` des Mandats.
  Bei Schritt 5 immer das `approval` des Mandats.

### 4.2 Bedingungen

Alle Bedingungen einer Regel müssen erfüllt sein. Geprüft wird in **Ortszeit des
Haushalts**: Der Zeitpunkt wird in die Zeitzone des Haushalts (IANA-Name, z. B.
`Europe/Berlin`) umgerechnet, die die Implementierung kennt. Fehlt sie, gilt der Offset, mit
dem der Zeitpunkt angegeben ist.

- `time_window`: `"HH:MM-HH:MM"`, minutengenau, Beginn einschließlich, Ende ausschließlich.
  `"06:00-22:00"` trifft 06:00 bis 21:59. Ist der Beginn größer als das Ende, geht das
  Fenster über Mitternacht: `"22:00-06:00"` trifft ab 22:00 und vor 06:00.
  Bei der Zeitumstellung zählt die Uhrzeit, die im Haushalt angezeigt wird; eine doppelt
  vorkommende Stunde trifft beide Male.
- `weekdays`: Liste aus `mon` … `sun`. Maßgeblich ist der Wochentag des Zeitpunkts in
  Ortszeit, auch bei Fenstern über Mitternacht (Freitag 22:00 bis Samstag 02:00 mit
  `weekdays: ["fri"]` trifft nur bis Mitternacht).

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
`paperless:document` mit `read`, `tag`, `delete`. Eine Erweiterung legt ihr Vokabular und
ihre kritischen Aktionen fest. Kennt eine Implementierung das Vokabular einer Erweiterung
nicht, ist jede Anfrage an eine Ressource dieser Kategorie `deny`.

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
  "context": { "outcome": "ask", "reason": "rule", "rule_id": "r-locks",
               "approval_timeout": "PT2M",
               "mandate_digest": "sha256:9f2c…" } }
```

`reason` und `mandate_digest` sind Pflicht, `rule_id` und `approval_timeout` stehen im
Kontext, wenn Abschnitt 4.1 sie vorsieht.

- `outcome: allow` → `decision: true`
- `outcome: ask` → `decision: false`, PEP muss eine Bestätigung einholen und darf nur bei
  positiver Antwort ausführen
- `outcome: deny` → `decision: false`

Ein PEP, der `ask` nicht kennt, behandelt die Antwort automatisch als Ablehnung. Damit ist
die Erweiterung abwärtskompatibel und sicher.

## 7. Transport im OAuth-Fluss (vorgesehen)

Ein Mandat kann als `authorization_details`-Objekt (RFC 9396) mit
`type: "https://mandate-spec.org/mandate/v0"` dargestellt werden, z. B. in der
Token-Introspektion oder wenn ein Agent bei der Anmeldung ein gewünschtes Mandat vorschlägt.
In v0.1 wählt immer der Mensch das Mandat; Vorschläge des Agenten sind nur Vorbelegung.

## 8. Konformität und Zertifizierung

`conformance/cases-v0.json` enthält die Fälle: Mandat + Anfrage + erwartete Entscheidung.
Pfade zu Mandaten sind relativ zum Wurzelverzeichnis dieses Repositorys. Die Sammlung wächst
mit jeder Version; jeder gefundene Fehler wird zuerst als Fall ergänzt.

Felder eines Falls:

| Feld | Pflicht | Bedeutung |
|---|---|---|
| `id` | ja | eindeutige Kennung |
| `mandate` / `mandate_inline` | eins davon | Pfad zum Mandat oder Mandat direkt im Fall |
| `resource` | ja | `entity_id`, `category`, `area` der Ressource |
| `action` | ja | angefragte Aktion |
| `time` | ja | Zeitpunkt nach RFC 3339 |
| `timezone` | nein | Zeitzone des Haushalts (IANA); fehlt sie, gilt der Offset in `time` |
| `revoked` | nein | `true`, wenn das Mandat widerrufen ist; Standard `false` |
| `expected` | ja | `allow`, `ask` oder `deny` |
| `reason` | ja | erwarteter Begründungscode nach Abschnitt 4.1 |
| `rule_id` | nein | erwartete `rule_id` nach Abschnitt 4.1; fehlt das Feld, wird sie nicht geprüft; `null` heißt: keine |
| `approval_timeout` | nein | erwartetes `timeout` der Freigabe-Einstellung bei `ask` |
| `why` | nein | Erklärung für Menschen |

`conformance/invalid-v0.json` enthält Mandate, die nach Abschnitt 3.1 ungültig sind und
abgelehnt werden müssen (`mandate_inline`, oder `mandate_raw` als Zeichenkette, wenn sich der
Fehler nicht als JSON-Objekt darstellen lässt, etwa doppelte Schlüssel).

`conformance/digest-v0.json` enthält Mandate mit ihrem erwarteten Fingerabdruck
(Abschnitt 3.2), `conformance/audit-v0.json` Protokolle mit dem erwarteten Ergebnis der
Kettenprüfung (Abschnitt 9.4).

Zwei Prüfwege:

1. **Bibliothek:** Implementierungen in Go können die Referenz-Auswertung aus diesem
   Repository einbinden oder ihre eigene Auswertung gegen die Fälle testen.
2. **Black-Box:** Das Prüfwerkzeug `mandate-conformance` spielt alle Fälle gegen den
   AuthZEN-Endpunkt einer beliebigen Implementierung ab, unabhängig von Sprache und Hersteller.
   Es lädt dazu die Mandate über eine Test-Schnittstelle, die in Abschnitt 10 definiert wird
   (folgt mit v0.2).

Eine Implementierung ist konform zu einer Version, wenn sie alle Fälle dieser Version besteht.
Der Prüfbericht ist maschinenlesbar und kann veröffentlicht werden. Ein formales
Zertifizierungsprogramm mit Logo folgt erst, wenn die Spezifikation eingefroren ist.

## 9. Protokoll

Jede Implementierung führt ein Protokoll, aus dem hervorgeht, **welcher Agent wann was auf
Grundlage welcher Konfiguration** getan hat. Format und Verkettung sind festgelegt, damit
Protokolle verschiedener Implementierungen mit denselben Werkzeugen geprüft werden können.
Maschinenlesbar: `schema/audit-v0.schema.json`.

### 9.1 Einträge

Jeder Eintrag ist ein JSON-Objekt mit `type: "https://mandate-spec.org/audit/v0"` und:

| Feld | Inhalt |
|---|---|
| `id` | UUIDv7 (RFC 9562) |
| `seq` | fortlaufende Nummer im Protokoll, beginnt bei 1, ohne Lücken |
| `recorded_at` | Zeitpunkt des Eintrags (RFC 3339) |
| `event` | Ereignisart (Abschnitt 9.2) |
| `principal` | Vollmachtgeber |
| `prev` | Fingerabdruck des vorherigen Eintrags (Abschnitt 9.4), beim ersten Eintrag `null` |

Je nach Ereignis kommen hinzu: `actor` (wer eine Änderung ausgelöst hat), `agent`,
`request` (Ressource, Aktion, Zeitpunkt, Zeitzone, Widerrufsstatus), `mandate` (`id`, `digest`, bei Änderungen
`previous_digest`), `evaluation` (Ergebnis nach Abschnitt 4.1), `approval` (Ausgang einer
Rückfrage), `result` (`executed`, `denied` mit `denied_by`, `failed` mit `error`),
`truncated` (Abschnitt 9.4).

Einträge enthalten **nie** Token, Nonces, Zugangsdaten oder den Inhalt eines Mandats.

### 9.2 Ereignisse

| `event` | Pflicht | Wann |
|---|---|---|
| `decision` | ja | jede Anfrage eines angemeldeten Agenten, auch wenn sie vor der Auswertung abgelehnt wird (z. B. Tempolimit, Not-Aus) |
| `mandate.created`, `mandate.updated`, `mandate.revoked` | ja | jede Änderung eines Mandats, mit Fingerabdruck alt und neu |
| `agent.registered`, `agent.revoked` | ja | Zulassung und Entzug eines Agenten |
| `emergency_stop.activated`, `emergency_stop.released` | ja | Not-Aus, sofern die Implementierung einen hat |
| `log.truncated` | ja | vor dem Löschen alter Einträge (Abschnitt 9.4) |
| `auth.rejected` | nein | abgewiesene Anmeldung oder ungültiges Token |

Bei `decision` stimmt `evaluation` mit dem Ergebnis überein, das die Auswertung (Abschnitt 4)
für `request` und die Fassung `mandate.digest` liefert. Damit lässt sich jede Entscheidung
nachrechnen.

### 9.3 Aufbewahrung

- Jede Mandatsfassung wird mindestens so lange aufbewahrt wie Einträge, die auf ihren
  Fingerabdruck verweisen.
- Wie lange Einträge aufbewahrt werden, legt die Implementierung fest. Gelöscht werden
  dürfen nur die ältesten Einträge (Abschnitt 9.4).

### 9.4 Verkettung und Prüfung

- Fingerabdruck eines Eintrags: `"sha256:" + hex(SHA-256(JCS(eintrag)))`, über den
  vollständigen Eintrag einschließlich `prev`.
- `prev` jedes Eintrags ist der Fingerabdruck seines Vorgängers; beim Eintrag mit `seq` 1
  ist `prev` `null`.
- Vor dem Löschen der Einträge bis einschließlich `seq` n wird ein Eintrag `log.truncated`
  mit `truncated: { up_to_seq: n, last_digest: <Fingerabdruck von Eintrag n> }` angefügt.
- Austauschformat: JSON Lines (ein Eintrag pro Zeile, UTF-8, aufsteigend nach `seq`).

Ein Protokoll ist **gültig**, wenn jeder Eintrag das Schema erfüllt und in Dateireihenfolge:

1. jeder Eintrag die `seq` seines Vorgängers plus 1 hat und `prev` dessen Fingerabdruck ist;
2. der erste Eintrag entweder `seq` 1 hat oder ein späterer Eintrag `log.truncated` mit
   `up_to_seq` = `seq` − 1 und `last_digest` = `prev` des ersten Eintrags vorhanden ist.

Ist ein Protokoll ungültig, meldet die Prüfung `broken_at`: die `seq` des ersten Eintrags
in Dateireihenfolge, der eine der Bedingungen verletzt.

Grenze: Die Verkettung zeigt Änderungen, Lücken und Umstellungen **innerhalb** des
Protokolls. Werden die neuesten Einträge entfernt oder der letzte geändert, erkennt sie das
nicht. Dafür muss das Ende der Kette außerhalb gesichert werden (Signatur oder Kopie); das
regelt eine spätere Version.

## 10. Test-Schnittstelle

Folgt mit v0.2.

## Änderungsprotokoll

### v0.1.0-alpha.1

Inkompatibel:
- `type` und Schema-`$id` auf die neutrale Domain verschoben:
  `https://mandate-spec.org/mandate/v0`. Name der Spezifikation: mandate-spec.
- Neue Gültigkeitsregeln für Mandate (Abschnitt 3.1): `format: date-time` wird geprüft,
  keine doppelten Schlüssel, eindeutige Regel-IDs, `time_window` mit verschiedenem Beginn und
  Ende, Aktionen passend zur Kategorie.

Präzisiert (Abschnitt 4), jeweils mit neuen Konformitätsfällen:
- Vorprüfung: unbekannte Kategorie, Aktion außerhalb des Vokabulars, ungültige Zeitangabe
  oder ungültiges Mandat → `deny`.
- Gültigkeitszeitraum `valid_from ≤ t < expires`; Widerruf als Eingabe der Auswertung.
- Ortszeit über die Zeitzone des Haushalts; Zeitfenster Beginn einschließlich, Ende
  ausschließlich; Wochentag des Zeitpunkts; Verhalten bei der Zeitumstellung.
- `rule_id` und Freigabe-Einstellung im Ergebnis (Abschnitt 4.1).
- `limits` gehören nicht zur Auswertung.
- Erweiterungen ohne bekanntes Vokabular → `deny`.

Neu:
- Fingerabdruck eines Mandats (Abschnitt 3.2), Begründungscodes (Abschnitt 4.1), beides
  Pflicht im AuthZEN-Antwortkontext (Abschnitt 6).
- Protokoll mit festem Format und Hash-Kette (Abschnitt 9, `schema/audit-v0.schema.json`).
- Schema: Zeitfelder zusätzlich mit `pattern`.

Konformitätsfälle: neue Felder `reason` (Pflicht), `timezone`, `revoked`, `rule_id`,
`approval_timeout`; neue Dateien `conformance/invalid-v0.json`, `conformance/digest-v0.json`,
`conformance/audit-v0.json`; Prüf-Mandate unter `conformance/mandates/`.
