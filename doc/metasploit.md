# `metasploit.py` – Metasploit-Modulmetadaten

## Quelle

Die Datei `db/modules_metadata_base.json` im GitHub-Repository `rapid7/metasploit-framework`. Sie
beschreibt jedes Modul mit Typ (`exploit`, `auxiliary`, `post`, `payload`, …) und Referenzliste. Die
URLs stammen aus der Konfiguration (`metasploit_commit_url`, `metasploit_commits_until_url`,
`metasploit_file_url`).

**Hinweis:** Die Commit-Auflösung nutzt die GitHub-API ohne Anmeldung. Dafür gelten 60 Anfragen je
Stunde und IP-Adresse.

## Schritt 1: Commit auflösen (`resolve_commit`)

Der Branch (Standard `master`) oder eine übergebene Commit-SHA wird über die GitHub-API aufgelöst. Aus
der JSON-Antwort werden die SHA (`sha`) und der Zeitpunkt des Committers (`commit.committer.date`)
gelesen und nach UTC umgerechnet. Fehlt etwas, bricht der Bezug mit `SourceError` ab.

### Stichtag: `commit_before(day)`

Wie bei Exploit-DB: Die Commit-Liste des Branches `master` bis `<Tag>T23:59:59Z` wird abgefragt
(ein Eintrag, der jüngste) und dessen SHA geliefert. Das dient den Stichtags-Snapshots der Evaluation
(AP-9.1).

## Schritt 2: Datei laden und zerlegen (`parse`)

Die Datei wird zu dieser Commit-SHA geladen (siehe [git_snapshot.md](git_snapshot.md)). Sie muss ein
JSON-Objekt sein, dessen Einträge die Module sind; andernfalls bricht der Bezug ab. Hat ein Modul keinen
Typ, bricht der Bezug ebenfalls ab.

Je Modul:

1. Die Kennung (`entry_id`) ist `fullname`, ersatzweise der Schlüssel im Objekt.
2. In `references` werden nur Texte betrachtet, die mit `CVE` beginnen.
3. Jede wird mit `common.normalize_cve` bereinigt. Ist das nicht möglich, wird sie **übersprungen und
   gezählt** (`skipped_count`).
4. Je Paar (CVE, Modul) entsteht eine Referenz; Doppelte werden zusammengefasst.

Übernommene Felder einer Referenz:

| Feld | Herkunft |
| --- | --- |
| `entry_id` | `fullname` bzw. Schlüssel |
| `entry_type` | `type` |
| `title` | `name` |
| `published` | `disclosure_date` |

Es werden alle Module mit CVE-Referenz gespeichert, gleich welchen Typs. Welche Typen als Nachweis
`e2_metasploit` zählen, legt die Einstellung `metasploit_module_types` fest (Standard: nur `exploit`,
Festlegung vom 13.09.2026). Scanner- und DoS-Module unter `auxiliary` machen die Ausnutzung nicht ohne
eigene Entwicklungsleistung verfügbar.

## Schritt 3: Speichern

Über `git_snapshot.sync`. Ohne `ref` wird der jüngste Stand von `master` bezogen und **nicht**
angeheftet; mit `ref` wird dieser Commit bezogen und **angeheftet**. Aufbewahrt werden die jüngsten
`exploit_keep_snapshots` (Standard 30) nicht angehefteten Snapshots.
