# vuln-prio-ci

Priorisierung von Sicherheitsbefunden als Stufe der GitLab-Pipeline eines Produkts.

Das Projekt liest die Sicherheitsberichte eines Pipeline-Laufs (SAST, Dependency Scanning, Container
Scanning) oder den CSV-Export des GitLab-Vulnerability-Reports und ordnet jeden Befund einer
Prioritätsstufe zu: **Sofort**, **Außerplanmäßig**, **Planmäßig** oder **Zurückgestellt**. Es läuft
als Kommandozeilenprogramm und als Image in einem Pipeline-Job.

## Funktionsweise

Jeder Befund durchläuft diese Schritte (`src/vuln_prio_ci/pipeline.py`):

1. **Einlesen** der GitLab-Sicherheitsberichte bzw. des CSV-Exports (`ingest/`).
2. **Kennung bestimmen** (`normalize/`): CVE, sonst EUVD/GHSA, sonst der CVE-lose Zweig mit
   Fingerabdruck als stabiler Identität.
3. **Einschätzungen anwenden**: VEX-Aussagen und Einschätzungen des Entwicklungsteams aus einer Datei
   im Repository des Produkts. Befunde mit VEX-Status `not_affected` oder `fixed` werden nicht
   priorisiert.
4. **Anreichern** (`enrich/`): EPSS, KEV, Exploit-DB, Metasploit und CVSS-Basiswert aus dem lokalen
   Referenzdatenspeicher.
5. **Entscheiden** (`decide/`): Die Prioritätsstufe und ein Rang kommen aus einer Regeltabelle.

Zwei Verfahren, je nachdem, ob eine CVE aufgelöst werden konnte:

| Verfahren | Fall | Eingang der Regeltabelle | Tabelle |
|---|---|---|---|
| 1 | mit CVE | Nachweisgrad (E1–E6) × CVSS-Bereich (C1–C3) | `rules/decision_table_cve.csv` (18 Zeilen) |
| 2 | ohne CVE | Ausnutzungslage × Erreichbarkeit × technische Auswirkung × Schutzbedarf | `rules/decision_table_cveless.csv` (54 Zeilen) |

Der Priorisierungslauf ruft **keine externen Dienste** auf. Die Informationen stammen aus einem täglich
erzeugten Informationspaket (siehe [Informationspaket](#informationspaket)). Ein Treffer ohne Regelzeile wird nicht auf
einen Standardwert abgebildet, sondern ist ein Fehler.

## Installation

Voraussetzung ist Python 3.15 (`requires-python >= 3.15`).

### Lokal (Windows)

```
py -3.15 -m venv .venv
.venv\Scripts\python -m pip install "pip @ https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
.venv\Scripts\python -m pip install -r requirements-dev.txt
.venv\Scripts\python -m pytest -q
```

**Der erste Schritt (pip auf 26.2.2) ist für jedes neue venv Pflicht**, siehe
[Sicherheitshinweis](#sicherheitshinweis-emudhraemsign-vorfall-oktober-2026).

Linux und macOS entsprechend mit `python3.15 -m venv .venv` und `.venv/bin/python`. Die Lock-Dateien
gelten für Linux x86_64 (Image und Pipeline). Lokal unter Windows stattdessen `requirements-dev.txt`
verwenden; dessen Untergrenzen erzwingen ebenfalls certifi ≥ 2026.10.19.

Wer das Paket als Befehl braucht:

```
pip install -e .
```

Danach stehen `vuln-prio-ci` (entspricht `python -m vuln_prio_ci`) und `vuln-prio-sources`
(entspricht `python -m vuln_prio_ci.sources`) zur Verfügung.

Liegt das venv unter einem sehr langen Pfad, scheitert `ensurepip` unter Windows an der
Pfadlängengrenze von 260 Zeichen (Fehler `No package metadata was found`). Dann das venv an einem
kürzeren Pfad anlegen oder lange Pfade in Windows freischalten.

### Image

```
docker build --pull --no-cache -t vuln-prio-ci .
```

Das Image (`python:3.15-slim`) installiert die Abhängigkeiten aus `requirements.lock` mit
`--require-hashes`. Der Bau bricht ab, wenn certifi oder pip nicht dem bereinigten Stand entsprechen.

### Konfiguration

Die Konfiguration kommt aus Umgebungsvariablen, in der Pipeline aus CI/CD-Variablen, lokal zusätzlich
aus einer `.env`-Datei. Vorlage ist `.env.example`.

| Variable | Standard | Bedeutung |
|---|---|---|
| `CACHE_DIR` | `./cache` | Ablage für `reference.sqlite`, KEV-Dump, Mapping und Manifest |
| `NVD_API_KEY` | leer | NVD-Schlüssel; beschleunigt den Bezug (50 statt 5 Abrufe je 30 s) |
| `EPSS_THRESHOLD` | `0.088` | EPSS-Schwelle für den Nachweisgrad |
| `CVSS_BAND_HIGH` | `7.0` | Untergrenze des CVSS-Bereichs C2 |
| `CVSS_BAND_CRITICAL` | `9.0` | Untergrenze des CVSS-Bereichs C3 |
| `EPSS_KEEP_SNAPSHOTS`, `EXPLOIT_KEEP_SNAPSHOTS` | `30` | aufbewahrte Snapshots je Quelle; `0` = alle |
| `METASPLOIT_MODULE_TYPES` | `exploit` | Modultypen, die als Metasploit-Nachweis zählen |

Die URLs der Quellen stehen ebenfalls in `.env.example`.

## Nutzung

### 1. Referenzdaten beziehen

Einzelne Quellen lokal (Ablage in `CACHE_DIR`):

```
python -m vuln_prio_ci.sources epss [--date YYYY-MM-DD]
python -m vuln_prio_ci.sources exploitdb [--ref SHA | --as-of YYYY-MM-DD]
python -m vuln_prio_ci.sources metasploit [--ref SHA | --as-of YYYY-MM-DD]
python -m vuln_prio_ci.sources kev
python -m vuln_prio_ci.sources nvd [--full]
python -m vuln_prio_ci.sources all
python -m vuln_prio_ci.sources manifest
python -m vuln_prio_ci.sources unpin epss YYYY-MM-DD
python -m vuln_prio_ci.sources unpin exploitdb|metasploit SHA
```

`all` bezieht alle Quellen mit jeweils jüngstem Stand; `manifest` schreibt `bundle-manifest.json`.
Ein ausdrücklich angefordertes Datum (`--date`, `--ref`, `--as-of`) wird angeheftet und von der
Aufbewahrung ausgenommen. `unpin` hebt die Anheftung wieder auf (Commit-SHA auch gekürzt) und wendet
sofort die Aufbewahrung an: Liegt der Snapshot außerhalb der jüngsten `*_KEEP_SNAPSHOTS`, wird er
gelöscht. NVD ohne `NVD_API_KEY`: 5 Abrufe je 30 s, ein Vollbezug dauert etwa eine
Viertelstunde; danach läuft der Abgleich inkrementell.

### 2. Befunde priorisieren

```
python -m vuln_prio_ci run --report-dir . --assessments security/prioritization-assessments.yaml \
    --max-age-days 2 --output prioritization.json --codequality gl-code-quality-report.json
```

| Option | Bedeutung |
|---|---|
| `--report FILE` | GitLab-Sicherheitsbericht (mehrfach möglich) |
| `--report-dir DIR` | Verzeichnis mit `gl-sast-report.json`, `gl-dependency-scanning-report.json`, `gl-container-scanning-report.json` |
| `--gitlab-csv FILE` | CSV-Export des Vulnerability Reports (Betriebsart 2) |
| `--assessments FILE` | Einschätzungsdatei (YAML) im Repository |
| `--output FILE` | Ergebnisdatei (JSON) |
| `--codequality FILE` | Code-Quality-Bericht für `artifacts:reports:codequality` |
| `--max-age-days N` | Höchstalter des Informationspakets in Tagen (Standard 2) |
| `--cve-only` | nur Befunde mit CVE (Verfahren 1) |
| `--default-exposure` | Erreichbarkeit, wenn keine angegeben ist (`remote`, `intern`, `lokal`; Standard `remote`) |
| `--online` | EUVD-Einzelabruf erlauben (Standard: aus) |
| `--cve ID` | einzelne CVE priorisieren (mehrfach möglich), Ausgabe nur im Terminal |

Einzelne CVEs ohne Bericht (Verfahren 1, CVSS-Basiswert aus der NVD im Referenzdatenspeicher):

```
python -m vuln_prio_ci run --cve CVE-2021-44228 --cve CVE-2023-0464
```

Das Ergebnis steht nur im Terminal: je CVE Stufe, Rang, CVSS-Basiswert und Begründung, auch für
Planmäßig und Zurückgestellt. Es entstehen keine Dateien; `--cve` lässt sich deshalb nicht mit
`--report`, `--report-dir`, `--gitlab-csv`, `--output` oder `--codequality` kombinieren. Die
Referenzdaten (Schritt 1) müssen vorhanden sein, die Exit-Codes gelten wie unten.

Zwei Betriebsarten:

- **Betriebsart 1**: Befunde des Pipeline-Laufs aus den Berichtsartefakten (`--report-dir`).
- **Betriebsart 2**: Bestand des Hauptzweigs aus dem CSV-Export (`--gitlab-csv … --cve-only`).

Den Export holt `python -m vuln_prio_ci export-inventory --project $CI_PROJECT_ID --output inventory.csv`
(Vulnerability Export API, nur Ultimate; braucht `GITLAB_API_TOKEN` mit Scope `read_api`).

**Testdaten:** `examples/cve-list.txt` enthält 344 CVE-Kennungen (270 verschiedene; Mehrfachnennungen
wie in einem Bestand, in dem eine CVE mehrere Pakete betrifft). `examples/cve-inventory.csv` ist
dieselbe Liste im Format des CSV-Exports, eine Zeile je Eintrag, ohne Paket und CVSS-Vektor. Nach
dem Bezug der Referenzdaten (Schritt 1):

```
python -m vuln_prio_ci run --gitlab-csv examples/cve-inventory.csv --cve-only --output prioritization.json
```

### 3. Ergebnis und Exit-Code

| Exit-Code | Bedeutung | in der Pipeline |
|---|---|---|
| 0 | kein Befund Sofort/Außerplanmäßig, alle entschieden, Paket aktuell | grün |
| 3 | Ergebnis eingeschränkt: Einschätzung fehlt oder Paket älter als `--max-age-days` | Warnung |
| 4 | mindestens ein Befund Außerplanmäßig | Warnung |
| 5 | mindestens ein Befund Sofort | Warnung |
| 1 | technischer Fehler: Bericht fehlt/ungültig, Informationspaket fehlt (bei CVE-Befunden), Einschätzungsdatei ungültig, certifi veraltet | Fehler |

Die Codes 3–5 stehen in `allow_failure:exit_codes`. Bei mehreren Bedingungen gilt der höchste Code.
Das Protokoll listet die Befunde der Stufen Sofort und Außerplanmäßig mit Begründung und gibt für
Befunde ohne Einschätzung eine ausfüllbare Vorlage aus. Der Code-Quality-Bericht zeigt die Befunde im
Merge Request (Sofort → blocker, Außerplanmäßig → critical, Planmäßig → major, Zurückgestellt →
minor, ohne Einschätzung → info).

### Einschätzungsdatei

Befunde ohne CVE brauchen eine Einschätzung des Entwicklungsteams (Ausnutzungslage, technische
Auswirkung, optional Erreichbarkeit), ebenso VEX-Aussagen. Die Datei liegt im Repository des Produkts,
üblich unter `security/prioritization-assessments.yaml`; ein Beispiel steht in
`examples/prioritization-assessments.yaml`.

Kennung eines Befunds in dieser Datei: ohne CVE `Regel-ID:Datei`, mit CVE `CVE:Paket`.

## Sicherheitshinweis: eMudhra/emSign-Vorfall (Oktober 2026)

Die Zwischenzertifikate von eMudhra unter der emSign-Wurzel hatten unsichere private Schlüssel. Wer
der Wurzel weiter vertraut, ist für Man-in-the-Middle-Angriffe auf TLS offen
([Hinweise der Python-Community](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576)).
Bereinigt sind **certifi ≥ 2026.10.19** und **pip ≥ 26.2.2**. pip lädt immer sein mitgeliefertes
certifi; `--cert`, `PIP_CERT` oder `REQUESTS_CA_BUNDLE` fügen nur Zertifikate hinzu und beheben das
nicht. Nur ein Update von pip hilft.

Umsetzung in diesem Projekt:
- **pip zuerst, über den Hash gesichert:** Image, Test-Job und die Anleitung oben heben pip vor jeder
  anderen Installation auf 26.2.2, mit Direkt-URL und `#sha256=…`. Der Hash schützt den Abruf auch
  dann, wenn das noch alte pip dabei einem falschen Zertifikat vertraut.
- **Abhängigkeiten mit Hashes:** `pip install --require-hashes -r requirements.lock`. Ein
  untergeschobenes Paket bricht die Installation ab.
- **certifi-Prüfung zur Laufzeit:** `fetch-bundle`, `publish-bundle`, `export-inventory`,
  `run --online` und alle Bezüge unter `python -m vuln_prio_ci.sources` brechen mit Exit-Code 1 ab,
  wenn certifi älter als 2026.10.19 ist (`src/vuln_prio_ci/tls.py`). Der Bau des Images bricht
  ebenfalls ab.
- **Image ohne Layer-Cache bauen:** `docker build --pull --no-cache`, `ca-certificates` wird im
  Image aktualisiert. Eine wöchentliche zeitgesteuerte Pipeline (`PRIO_JOB=rebuild-image`) hält
  Basis-Image und Systemzertifikate aktuell.
- **Kein Dependency-Cooldown für certifi und pip:** Mit Cooldowns bleibt man bis zum Update
  verwundbar. Bei einem neuen Sicherheits-Release sofort `scripts/lock.py` laufen lassen und
  `PIP_WHEEL` (Dockerfile, `.gitlab-ci.yml`) anpassen.

Python 3.15.1 liefert pip 26.2.2 über `ensurepip` mit; unter 3.15.0 bekommt ein neues venv noch
pip 26.2.1. Der erste Installationsschritt ist deshalb für jedes neue venv Pflicht.

## Aufbau

```
vuln-prio-ci/
├── src/vuln_prio_ci/
│   ├── __main__.py            CLI: python -m vuln_prio_ci run|fetch-bundle|publish-bundle|export-inventory
│   ├── tls.py                 Mindeststand certifi (eMudhra/emSign)
│   ├── config.py              Konfiguration (Umgebungsvariablen, lokal .env)
│   ├── pipeline.py            Orchestrierung: Kennung, VEX, Anreicherung, Entscheidung
│   ├── ci/                    run.py (Lauf, Exit-Codes), freshness.py (Alter des Informationspakets),
│   │                          codequality.py (Bericht für den Merge Request), gitlab_api.py
│   │                          (Generic Package Registry, Vulnerability Export API)
│   ├── ingest/                GitLab-Sicherheitsberichte, CSV-Export, Einschätzungsdatei
│   ├── normalize/             Kennungshierarchie CVE/EUVD/GHSA/CWE, Fingerabdruck
│   ├── enrich/                CVSS, EPSS, KEV, Exploit-DB/Metasploit, NVD, EUVD (nur Nachschlagen)
│   ├── decide/                Nachweisgrad, Schutzbedarf, Regeltabellen, Entscheidung
│   ├── rules/                 decision_table_cve.csv (18 Zeilen), decision_table_cveless.csv (54 Zeilen)
│   ├── sources/               Bezug der Referenzdaten: python -m vuln_prio_ci.sources <quelle>|all|manifest
│   ├── store/                 Referenzdatenspeicher (SQLite, CACHE_DIR/reference.sqlite)
│   └── models/                Pydantic-Schemata und Enums
├── doc/                       Dokumentation der Datenerhebung je Skript in src/vuln_prio_ci/sources
├── templates/prioritize.gitlab-ci.yml   Vorlage zum Einbinden in Produkt-Pipelines
├── examples/                  product.gitlab-ci.yml, prioritization-assessments.yaml,
│                              cve-list.txt + cve-inventory.csv (Testdaten)
├── .gitlab-ci.yml             eigene Pipeline: Tests, Image, tägliches Informationspaket
├── Dockerfile                 Image für die Jobs (kein Dienst, kein Port)
├── requirements*.txt          Untergrenzen; requirements*.lock: feste Versionen mit Hashes
├── scripts/lock.py            erzeugt die Lock-Dateien
└── tests/
```

## Informationspaket

Der Priorisierungslauf ruft keine externen Dienste auf. Die Informationen kommen aus einem täglich
erzeugten Informationspaket. Die zeitgesteuerte Pipeline dieses Projekts (`PRIO_JOB=reference-bundle`)
bezieht alle Quellen und veröffentlicht das Paket in der Generic Package Registry dieses Projekts
(`reference-bundle/<Zeitstempel>/reference-bundle.tar.gz`):

```
python -m vuln_prio_ci.sources all
python -m vuln_prio_ci publish-bundle --project "$CI_PROJECT_ID"
```

Der Produkt-Job lädt die jüngste Version mit dem Job-Token:

```
python -m vuln_prio_ci fetch-bundle --project <ID oder Pfad von vuln-prio-ci>
```

Dafür muss vuln-prio-ci die Produktprojekte in der Job-Token-Zulassung führen
(Settings > CI/CD > Job token permissions).

Wie die Daten je Quelle erhoben werden, steht in [doc/](doc/README.md).

## Einbindung in die Produkt-Pipeline

- `templates/prioritize.gitlab-ci.yml` per `include: project/file` einbinden, zwei Jobs:
  - `vuln-prioritize` (Betriebsart 1): Befunde des Laufs aus den Berichtsartefakten von SAST,
    Dependency Scanning und Container Scanning, Einschätzungsdatei aus dem Repository.
  - `vuln-prioritize-inventory` (Betriebsart 2): zeitgesteuert (`PRIO_INVENTORY=true`), exportiert
    den Bestand des Hauptzweigs über die Vulnerability Export API (`GITLAB_API_TOKEN`, Scope
    `read_api`) und priorisiert die Befunde mit CVE neu (`--cve-only`).
- `examples/product.gitlab-ci.yml` zeigt ein Produkt. **Wichtig:** Die GitLab-Vorlagen für SAST und
  Dependency Scanning legen ihre Berichte nur unter `artifacts:reports` ab; Folgejobs erhalten sie
  dann nicht (https://gitlab.com/gitlab-org/gitlab/-/issues/243717). Die Scanner-Jobs sind um
  `artifacts:paths` zu ergänzen.
- `examples/prioritization-assessments.yaml`: Einschätzungsdatei (Verfahren 2 und VEX-Aussagen),
  im Produkt unter `security/prioritization-assessments.yaml`.

## Abhängigkeiten festschreiben

`requirements.txt`/`requirements-dev.txt` enthalten Untergrenzen, die Lock-Dateien feste Versionen
mit SHA-256 für Linux x86_64 und CPython 3.15. Nach jeder Änderung der Untergrenzen und bei
Sicherheits-Releases neu erzeugen (braucht pip ≥ 26.2.2):

```
python scripts/lock.py
```

Die Abhängigkeiten sind `pydantic`, `pydantic-settings`, `httpx`, `ruamel.yaml` (reines Python,
sicherer Lader; doppelte Schlüssel in der Einschätzungsdatei sind ein Fehler) und `certifi`.

## Geprüft

- 179 Tests unter Python 3.15 (Windows), auch mit Deprecation-Warnungen als Fehler.
- Lock-Dateien gegen PyPI aufgelöst (alle Pakete als Wheel für cp315/manylinux verfügbar).

Nicht geprüft: Image-Build, Lauf in einer echten GitLab-Instanz, echter Bericht des eingesetzten
Dependency-Scanning-Analysators, NVD gegen die echte API.
