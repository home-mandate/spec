# mandate-spec

Herstellerneutrale Spezifikation für **Mandate von Software-Agenten im Haushalt**: was ein
KI-Agent im Auftrag eines Haushalts tun darf, mit den Entscheidungen erlauben, nachfragen und
verbieten, plus Prüfwerkzeuge, mit denen jede Implementierung ihre Konformität nachweist.

Arbeitstitel, der endgültige neutrale Name folgt vor der ersten Veröffentlichung.
Status: Entwurf v0. Referenzimplementierung: Home-Mandate.

## Inhalt

| Pfad | Inhalt | Lizenz |
|---|---|---|
| `SPEC-v0.md` | Spezifikation: Datenmodell, Auswertungsregel, Vokabular, AuthZEN-Abbildung | CC BY 4.0 |
| `schema/mandate-v0.schema.json` | JSON-Schema (Draft 2020-12) | Apache 2.0 |
| `examples/` | Beispiel-Mandate | Apache 2.0 |
| `conformance/cases-v0.json` | Konformitätsfälle | Apache 2.0 |
| `evaluator/` *(geplant, v0.1)* | Referenz-Auswertung als Go-Bibliothek, ohne Abhängigkeiten außer der Standardbibliothek | Apache 2.0 |
| `cmd/mandate-conformance/` *(geplant, v0.2)* | Black-Box-Prüfwerkzeug gegen beliebige AuthZEN-Endpunkte | Apache 2.0 |

## Warum ein eigenes Repository

- **Neutralität:** Andere Hersteller übernehmen einen Standard eher, wenn er nicht im
  Produkt-Repository eines Wettbewerbers liegt.
- **Lizenz:** Apache 2.0 mit Patentklausel für alles, was andere einbinden; das Produkt selbst
  bleibt AGPL.
- **Versionierung:** Die Spezifikation hat einen eigenen, langsameren Takt (Tags `v0.1.0` …).
  Implementierungen beziehen sich auf eine konkrete Version.
- **Glaubwürdigkeit der Prüfung:** Prüffälle und Prüfwerkzeug werden unabhängig vom Produkt
  gepflegt; auch Home-Mandate muss sie bestehen.

## Regeln für Änderungen

- Jede Änderung an der Auswertungsregel braucht neue oder geänderte Konformitätsfälle.
- Fehler in einer Implementierung, die auf eine Unschärfe der Spezifikation zurückgehen, werden
  zuerst hier präzisiert.
- Bis v1.0 sind inkompatible Änderungen erlaubt, müssen aber im Änderungsprotokoll stehen.
