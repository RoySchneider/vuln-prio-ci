# `__main__.py` – Kommandozeile für den Bezug

Mit `python -m vuln_prio_ci.sources <Quelle>` werden die Bezugsskripte angestoßen, manuell oder
zeitgesteuert.

## Befehle

| Befehl | Wirkung |
| --- | --- |
| `epss` | jüngste EPSS-Tagesdatei beziehen |
| `epss --date JJJJ-MM-TT` | Tagesdatei eines Stichtags beziehen (wird angeheftet) |
| `exploitdb [--ref SHA]` | Exploit-DB: Branch `main` bzw. angegebener Commit (angeheftet) |
| `metasploit [--ref SHA]` | Metasploit: Branch `master` bzw. angegebener Commit (angeheftet) |
| `exploitdb`/`metasploit` `--as-of JJJJ-MM-TT` | letzter Commit bis Ende des Stichtags (angeheftet), für die Evaluation zum Beobachtungszeitpunkt T |
| `kev` | KEV-Dump laden (kumulativ, kein Snapshot und keine Anheftung nötig) |
| `nvd [--full]` | CVSS-Basiswerte der NVD, inkrementell bzw. vollständig |
| `all` | alle Quellen mit jeweils jüngstem Stand (für den Zeitplan) |
| `manifest` | `bundle-manifest.json` in `CACHE_DIR` schreiben |
| `unpin epss JJJJ-MM-TT` | Anheftung eines EPSS-Snapshots aufheben, danach Aufbewahrung anwenden |
| `unpin exploitdb`/`metasploit SHA` | Anheftung eines Exploit-Snapshots aufheben (SHA auch gekürzt, muss eindeutig sein), danach Aufbewahrung anwenden |

`--ref` und `--as-of` schließen einander aus.

## Ablauf

1. **Manifest und Anheftung**: `manifest` schreibt nur das Manifest und endet. `unpin` arbeitet nur
   auf `reference.sqlite` (ohne Netzzugriff und ohne CA-Prüfung) und endet mit Exit-Code 1, wenn der
   Snapshot unbekannt oder die gekürzte SHA mehrdeutig ist.
2. **CA-Bundle prüfen**: Vor jedem Netzzugriff wird geprüft, dass das installierte `certifi` nicht
   älter als 2026.10.19 ist (eMudhra/emSign-Vorfall, `tls.py`). Ist es älter, endet der Befehl mit
   Fehlermeldung und Exit-Code 1.
3. **Quellen ausführen**: Bei `all` in dieser Reihenfolge: EPSS, Exploit-DB, Metasploit, KEV, NVD.
   Die Quellen laufen unabhängig voneinander; scheitert eine, werden die übrigen trotzdem versucht.
   `manifest` gehört nicht zu `all` und wird extra aufgerufen.

## KEV-Dump

Der KEV-Dump wird nicht in `sources/` erhoben, sondern über `enrich/kev.py::refresh`. Er stammt vom
Endpunkt `<euvd_base_url>/kev/dump` der EUVD (ENISA), der CISA KEV und EU KEV vereint. Die Datei wird
unverändert als `kev-dump.json` im Cache-Verzeichnis abgelegt; schlägt der Abruf fehl, ist das ein
Bezugsfehler.

## Ausgabe und Exit-Code

Je Quelle wird eine Zusammenfassung ausgegeben, zum Beispiel Zahl der CVEs bzw. Referenzen, ob der
Snapshot gespeichert wurde oder unverändert war, und welche Snapshots entfernt wurden.

| Exit-Code | Bedeutung |
| --- | --- |
| `0` | alle gewählten Quellen erfolgreich |
| `1` | mindestens ein Bezug fehlgeschlagen oder CA-Bundle veraltet |
