# `common.py`

Dieses Skript erhebt selbst keine Daten. Es stellt die Funktionen bereit, die alle Bezugsskripte nutzen.

## HTTP-Abruf

- **`download(url)`** lädt eine Datei per `httpx.get` (Weiterleitungen werden verfolgt, Zeitlimit
  60 s) und liefert Inhalt und die URL nach der Weiterleitung. Letztere wird als Herkunft im Snapshot
  gespeichert.
- **`get_json(url)`** nutzt `download` und liest die Antwort als JSON.

Fehlerbehandlung: Jeder Fehler wird als `SourceError` gemeldet.

| Fall | Meldung |
| --- | --- |
| Netzwerkfehler | „Abruf fehlgeschlagen" |
| HTTP 403 oder 404 | „nicht gefunden" (EPSS beantwortet ein Datum ohne Datei mit 403) |
| anderer HTTP-Fehlerstatus | „Abruf fehlgeschlagen (HTTP …)" |
| keine gültige JSON-Antwort | „keine gültige JSON-Antwort" |

## CVE-Bereinigung

**`normalize_cve(value)`** bereinigt eine CVE-Angabe aus Freitextfeldern (Exploit-DB, Metasploit):

1. Alle Leerzeichen entfernen (`CVE-2015- 5698` wird `CVE-2015-5698`).
2. In Großbuchstaben umwandeln.
3. Satzzeichen am Ende entfernen (`.`, `,`, `;`, `:`).
4. Gegen das Muster `CVE-JJJJ-NNNN…` (mindestens vier Ziffern am Ende) prüfen.

Passt das Ergebnis nicht, liefert die Funktion `None`, etwa bei Platzhaltern wie `CVE-n/a`.

## Zeitstempel

- **`utc_timestamp(value)`** wandelt einen ISO-8601-Zeitstempel beliebiger Zone nach UTC um, auf die
  Sekunde genau. Ein nachgestelltes `Z` wird akzeptiert, ein Zeitstempel ohne Zone gilt als UTC. Das
  Ergebnis lässt sich als Text sortieren.
- **`now_utc()`** liefert die aktuelle Zeit im gleichen Format. Sie dient als `fetched_at` (Zeitpunkt
  des Bezugs).
