# Dokumentation: Datenerhebung in `src/vuln_prio_ci/sources`

Die Skripte in `src/vuln_prio_ci/sources/` beziehen die externen Referenzdaten, die der
Priorisierungslauf später nachschlägt. Der Bezug läuft **getrennt vom Priorisierungslauf**: Der Lauf
selbst ruft keine externen Dienste auf, er liest nur den lokalen Referenzdatenspeicher.

## Überblick

| Skript | Quelle | Inhalt | Dokument |
| --- | --- | --- | --- |
| `common.py` | – | gemeinsame Bausteine (HTTP-Abruf, CVE-Bereinigung, Zeitstempel) | [common.md](common.md) |
| `epss.py` | FIRST EPSS | tägliche Ausnutzungswahrscheinlichkeit je CVE | [epss.md](epss.md) |
| `git_snapshot.py` | – | gemeinsamer Ablauf für Quellen, die als Datei in einem Git-Repository liegen | [git_snapshot.md](git_snapshot.md) |
| `exploitdb.py` | Exploit-DB (GitLab) | öffentliche Exploits mit CVE-Bezug | [exploitdb.md](exploitdb.md) |
| `metasploit.py` | Metasploit (GitHub) | Metasploit-Module mit CVE-Bezug | [metasploit.md](metasploit.md) |
| `nvd.py` | NVD CVE API 2.0 | CVSS-Basiswerte je CVE | [nvd.md](nvd.md) |
| `manifest.py` | – | Stand des Informationspakets (`bundle-manifest.json`) | [manifest.md](manifest.md) |
| `__main__.py` | – | Kommandozeile, die die Bezüge anstößt | [main.md](main.md) |

Der KEV-Dump wird nicht in `sources/` erhoben, sondern in `enrich/kev.py` (EUVD-Dump). Der Aufruf
läuft aber über dieselbe Kommandozeile; siehe [main.md](main.md).

## Gemeinsames Prinzip

1. **Abruf**: Eine Datei oder API-Seite wird per HTTP geladen (`common.download`, `common.get_json`).
2. **Prüfung**: Der Inhalt wird vollständig geprüft, bevor etwas gespeichert wird. Ein Fehler
   verwirft den ganzen Bezug (`SourceError`), damit kein halber Snapshot entsteht.
3. **Ablage**: Das Ergebnis landet in der SQLite-Datei `reference.sqlite` im Cache-Verzeichnis
   (`CACHE_DIR`, Standard `./cache`), siehe `src/vuln_prio_ci/store/`. Die Datenbank läuft im
   WAL-Modus, sodass gelesen werden kann, während ein Bezug schreibt.
4. **Aufbewahrung**: Je Quelle bleiben die jüngsten `keep` Snapshots erhalten. Ausdrücklich für ein
   Datum oder einen Commit bezogene Snapshots sind **angeheftet** (`pinned`) und werden nie entfernt.
5. **Manifest**: Erst danach wird `bundle-manifest.json` geschrieben (`manifest.py`), das den Stand
   jeder Quelle festhält.

## Konfiguration

Alle URLs und Aufbewahrungsgrenzen stehen in `src/vuln_prio_ci/config.py` und lassen sich über
Umgebungsvariablen oder `.env` überschreiben.

| Einstellung | Standard | Verwendet von |
| --- | --- | --- |
| `epss_bulk_base_url` | `https://epss.empiricalsecurity.com` | `epss.py` |
| `epss_keep_snapshots` | `30` | `epss.py` |
| `exploitdb_commit_url`, `exploitdb_commits_until_url`, `exploitdb_file_url` | GitLab-API bzw. Raw-Datei | `exploitdb.py` |
| `metasploit_commit_url`, `metasploit_commits_until_url`, `metasploit_file_url` | GitHub-API bzw. Raw-Datei | `metasploit.py` |
| `exploit_keep_snapshots` | `30` | `exploitdb.py`, `metasploit.py` |
| `nvd_api_url` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | `nvd.py` |
| `nvd_api_key` | leer | `nvd.py` |
| `cache_dir` | `./cache` | alle |

Der Wert `0` bei `*_keep_snapshots` bedeutet: nichts entfernen, alle Snapshots behalten.
