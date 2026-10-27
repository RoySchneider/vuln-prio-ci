# `git_snapshot.py` – gemeinsamer Ablauf für Git-Quellen

Exploit-DB und Metasploit liegen als Datei in einem Git-Repository vor. Dieses Skript enthält den
Ablauf, den beide teilen (`sync`). Die quellenspezifischen Teile, nämlich Commit auflösen und Datei
zerlegen, liefern `exploitdb.py` und `metasploit.py`.

## Datentypen

| Typ | Bedeutung |
| --- | --- |
| `Commit` | Commit-SHA und Commit-Zeitpunkt (UTC) |
| `ParseResult` | gefundene CVE-Referenzen und Anzahl der übersprungenen Angaben |
| `SyncResult` | gespeicherter Snapshot, ob er neu gespeichert wurde, und die entfernten Commits |

## Ablauf von `sync`

1. **Prüfen, ob der Commit schon gespeichert ist.** Falls ja, wird nichts geladen. Soll der Snapshot
   angeheftet sein, wird er angeheftet; danach greift die Aufbewahrung. Ergebnis: `stored = False`.
2. **Datei laden.** Die URL-Vorlage (`…/{ref}/…`) wird mit der **Commit-SHA** gefüllt, nicht mit dem
   Branch-Namen. So stimmen Inhalt und gespeicherter Commit sicher überein, auch wenn der Branch
   zwischen Auflösung und Abruf weiterläuft.
3. **Zerlegen** mit der quellenspezifischen Funktion `parse`. Enthält die Datei keine einzige
   CVE-Referenz, bricht der Bezug mit `SourceError` ab.
4. **Snapshot anlegen** mit Quelle, Commit-SHA, Commit-Zeitpunkt, URL nach Weiterleitung, SHA-256 der
   Datei, Anzahl der Referenzen, Anzahl übersprungener Angaben, Bezugszeitpunkt und Anheftung.
5. **Speichern** von Snapshot und Referenzen in einer Transaktion (alles oder nichts).
6. **Aufbewahrung** anwenden: Es bleiben die jüngsten `keep` nicht angehefteten Snapshots.

## Ergebnis

Tabellen `exploit_snapshot` (ein Eintrag je Quelle und Commit) und `exploit_reference` (je Snapshot
die CVE-Referenzen mit Eintragskennung, Typ, Titel, Veröffentlichungsdatum und `verified`).
Gespeichert wird **ungefiltert**; welche Eintragstypen als Nachweis zählen, entscheidet erst das
Nachschlagen (`enrich/exploits.py`).
