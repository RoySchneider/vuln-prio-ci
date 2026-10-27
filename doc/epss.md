# `epss.py` – EPSS-Tagesdateien

## Quelle

Die Bulk-Dateien von FIRST EPSS:

```
<epss_bulk_base_url>/epss_scores-<JJJJ-MM-TT>.csv.gz   Datei eines bestimmten Tages
<epss_bulk_base_url>/epss_scores-current.csv.gz        Weiterleitung auf die jüngste Tagesdatei
```

Ein Abruf je Tag ersetzt Einzelabrufe über die FIRST-API je CVE. Für ein Datum ohne Datei antwortet
der Server mit HTTP 403.

## Ablauf von `sync(day=None)`

1. **Abruf**: Die Datei zum Tag `day` wird geladen, ohne Angabe die jüngste (`-current`).
2. **Entpacken**: gzip entpacken und als UTF-8 lesen (mit oder ohne BOM). Schlägt das fehl, bricht der
   Bezug mit `EpssSourceError` ab.
3. **Prüfen und Zerlegen** (`parse`): siehe unten. Die Datei wird vollständig geprüft, bevor etwas
   gespeichert wird.
4. **Bezugsdatum bestimmen**: Es stammt aus der Kommentarzeile der Datei. Das Datum aus dem
   Dateinamen der Weiterleitung muss dazu passen, sonst bricht der Bezug ab. Fehlt die Kommentarzeile
   (ältere Dateien), gilt das Datum aus dem Dateinamen. Fehlt beides, bricht der Bezug ab.
5. **Snapshot anlegen**: Bezugsdatum, Modellversion, Zeitstempel, Herkunfts-URL, SHA-256 der
   bezogenen Datei, Zeilenzahl, Bezugszeitpunkt. `pinned` ist gesetzt, wenn ein Datum ausdrücklich
   angefordert wurde.
6. **Speichern**: Der Snapshot wird nur geschrieben, wenn für das Datum noch keiner existiert oder
   sich die SHA-256 unterscheidet. Ist er identisch, wird höchstens die Anheftung nachgetragen.
7. **Aufbewahrung**: Es bleiben die jüngsten `epss_keep_snapshots` (Standard 30) nicht angehefteten
   Snapshots; ältere werden entfernt.

## Dateiformat und Prüfung (`parse`)

| Variante | Aufbau |
| --- | --- |
| aktuell | Kommentarzeile `#model_version:v2026.06.15,score_date:2026-09-12T12:00:22Z`, dann Kopfzeile `cve,epss,percentile` |
| älter | Kopfzeile `cve,epss,percentile` oder nur `cve,epss`, ohne Kommentarzeile (Modellversion unbekannt) |

Geprüft wird je Zeile:

- Die Kopfzeile ist eine der beiden erlaubten (ohne Beachtung von Groß-/Kleinschreibung).
- Die Spaltenzahl entspricht der Kopfzeile. Leere Zeilen werden übersprungen.
- Die CVE-Kennung hat das Muster `CVE-JJJJ-NNNN…` und wird in Großbuchstaben gespeichert.
- EPSS-Wert und Perzentil sind Zahlen im Bereich 0 bis 1 (NaN fällt heraus).
- Die Datei enthält mindestens einen Wert.

**Eine fehlerhafte Zeile verwirft den ganzen Bezug.** Ein halber Snapshot würde EPSS-Werte
stillschweigend als unbekannt erscheinen lassen.

## Ergebnis

Tabellen `epss_snapshot` (ein Eintrag je Bezugsdatum) und `epss_score` (CVE, EPSS, Perzentil je
Bezugsdatum). Alle Werte eines Priorisierungslaufs stammen aus genau einem Snapshot. Fehlt die CVE
dort, ist der EPSS-Wert unbekannt; auf ältere Snapshots wird nicht zurückgegriffen.
