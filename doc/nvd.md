# `nvd.py` – CVSS-Basiswerte aus der NVD

## Quelle

Die CVE API 2.0 der NVD (`nvd_api_url`, Standard `https://services.nvd.nist.gov/rest/json/cves/2.0`).
Der Abruf erfolgt per `GET`; ist ein API-Schlüssel gesetzt (`nvd_api_key`), wird er im Header `apiKey`
mitgesendet. Zeitlimit je Abruf: 120 s.

## Auswahl der Bewertung je CVE (`select_metric`)

Je CVE wird genau **eine** Bewertung gespeichert, nach der Festlegung in Kapitel 5:

1. Version 3.x vor 4.0.
2. Innerhalb einer Version die Primärbewertung (`Primary`) vor der Zweitbewertung (`Secondary`).
3. Bei 3.x die Version 3.1 vor 3.0.

Bewertungen nach CVSS 2.0 werden nicht übernommen, weil die CVSS-Bereiche des Verfahrens 1 für 3.x und
4.0 definiert sind. Eine CVE nur mit 2.0-Bewertung gilt als ohne CVSS-Basiswert. Einträge ohne
`baseScore` werden ignoriert.

Gespeichert werden Basiswert, Vektor, Version, Bewertungsart, bewertende Stelle, Änderungszeitpunkt des
CVE-Datensatzes laut NVD und der Bezugszeitpunkt.

## Ablauf von `sync(full=False)`

1. **Umfang bestimmen.**
   - **Vollbezug**, wenn `full` gesetzt ist oder noch nie abgeglichen wurde: der gesamte Bestand, ohne
     Zeitfenster.
   - **Inkrementell** sonst: ab dem letzten Abgleich (`synced_until`) minus **1 Stunde Überlappung**,
     damit kein Datensatz an der Fenstergrenze fehlt. Die Anfragen laufen über `lastModStartDate` und
     `lastModEndDate`, in Fenstern von **höchstens 120 Tagen** (Grenze der API).
2. **Seitenweise abrufen.** Pro Abruf höchstens 2000 Einträge (`resultsPerPage`), fortgesetzt über
   `startIndex`, bis `totalResults` erreicht ist.
3. **Pausen einhalten.** Ohne API-Schlüssel erlaubt die NVD 5 Abrufe je 30 s, mit Schlüssel 50. Der
   Bezug wartet deshalb 6,1 s bzw. 0,7 s zwischen den Abrufen. Ein Vollbezug dauert ohne Schlüssel
   rund eine Viertelstunde; für den Zeitplan sollte `NVD_API_KEY` gesetzt werden.
4. **Je Seite auswerten.** Für jeden Eintrag wird die Bewertung ausgewählt.
   - Gibt es eine verwendbare Bewertung, wird sie eingefügt bzw. aktualisiert.
   - Gibt es keine (mehr), wird ein vorhandener Eintrag der CVE **gelöscht** (`removed`).
   - Einträge ohne CVE-Kennung werden übersprungen.
   Schreiben und Löschen einer Seite laufen in einer Transaktion.
5. **Stand festhalten.** Am Ende werden `synced_until` (aktuelle Zeit, UTC), der Bezugszeitpunkt und
   die Angabe, ob es ein Vollbezug war, gespeichert (Tabelle `nvd_sync`). Der Merker „Vollbezug"
   bleibt gesetzt, auch wenn später inkrementell abgeglichen wird.

## Fehler

Netzwerkfehler, HTTP-Fehlerstatus und Antworten, die kein gültiges JSON sind, führen zu `SourceError`.
Der Stand `synced_until` wird dann nicht fortgeschrieben; bereits abgeschlossene Seiten bleiben
gespeichert.

## Ergebnis

Tabelle `nvd_cvss` (eine Zeile je CVE) und `nvd_sync` (eine Zeile). Liegt für eine CVE kein Eintrag
vor, bleibt der Basiswert aus dieser Quelle unbekannt; die Pipeline greift dann auf den Vektor aus dem
Bericht zurück.
