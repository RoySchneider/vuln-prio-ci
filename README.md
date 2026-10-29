# vuln-prio-ci

Prioritization of security findings as a stage of a product's GitLab pipeline.

The project reads the security reports of a pipeline run (SAST, Dependency Scanning, Container
Scanning) or the CSV export of the GitLab Vulnerability Report and assigns each finding to a
priority level: **Sofort** (immediate), **Außerplanmäßig** (out of schedule), **Planmäßig**
(scheduled) or **Zurückgestellt** (deferred). It runs as a command-line program and as an image in a
pipeline job. The level names are the values the tool outputs and are kept in German below.

## How it works

Each finding goes through these steps (`src/vuln_prio_ci/pipeline.py`):

1. **Ingest** the GitLab security reports or the CSV export (`ingest/`).
2. **Determine the identifier** (`normalize/`): CVE, otherwise EUVD/GHSA, otherwise the CVE-less
   branch with a fingerprint as stable identity.
3. **Apply assessments**: VEX statements and assessments by the development team from a file in the
   product's repository. Findings with VEX status `not_affected` or `fixed` are not prioritized.
4. **Enrich** (`enrich/`): EPSS, KEV, Exploit-DB, Metasploit and CVSS base score from the local
   reference data store.
5. **Decide** (`decide/`): The priority level and a rank come from a rule table.

Two methods, depending on whether a CVE could be resolved:

| Method | Case | Input of the rule table | Table |
|---|---|---|---|
| 1 | with CVE | evidence level (E1–E6) × CVSS band (C1–C3) | `rules/decision_table_cve.csv` (18 rows) |
| 2 | without CVE | exploitation status × reachability × technical impact × protection need | `rules/decision_table_cveless.csv` (54 rows) |

The prioritization run calls **no external services**. The information comes from a daily generated
information bundle (see [Information bundle](#information-bundle)). A hit without a rule row is not
mapped to a default value but is an error.

## Installation

Python 3.15 is required (`requires-python >= 3.15`).

### Local (Windows)

```
py -3.15 -m venv .venv
.venv\Scripts\python -m pip install "pip @ https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
.venv\Scripts\python -m pip install -r requirements-dev.txt
.venv\Scripts\python -m pytest -q
```

**The first step (pip to 26.2.2) is mandatory for every new venv**, see
[Security notice](#security-notice-emudhraemsign-incident-october-2026).

On Linux and macOS use `python3.15 -m venv .venv` and `.venv/bin/python` accordingly. The lock files
apply to Linux x86_64 (image and pipeline). Locally on Windows use `requirements-dev.txt` instead;
its lower bounds also enforce certifi ≥ 2026.10.19.

If you need the package as a command:

```
pip install -e .
```

This provides `vuln-prio-ci` (equivalent to `python -m vuln_prio_ci`) and `vuln-prio-sources`
(equivalent to `python -m vuln_prio_ci.sources`).

If the venv is located under a very long path, `ensurepip` on Windows fails at the 260-character path
length limit (error `No package metadata was found`). In that case create the venv at a shorter path
or enable long paths in Windows.

### Image

```
docker build --pull --no-cache -t vuln-prio-ci .
```

The image (`python:3.15-slim`) installs the dependencies from `requirements.lock` with
`--require-hashes`. The build aborts if certifi or pip do not match the patched version.

The image contains a command-line program, not a service: every `docker run` executes one command and
exits. Without a command it prints the help. The reference data store as well as reports and result
files live on the host and are mounted in; `CACHE_DIR` points to the mounted directory, otherwise the
store is lost with the container. The container reads a local `.env` only via `--env-file .env`; a
`-e` takes precedence over values from the file. Examples for PowerShell from the repository root
(on Linux/macOS use `\` instead of the backtick for line continuation):

```
docker run --rm vuln-prio-ci

docker run --rm -v "${PWD}\cache:/data/cache" -e CACHE_DIR=/data/cache --env-file .env `
    vuln-prio-ci python -m vuln_prio_ci.sources all

docker run --rm -v "${PWD}\cache:/data/cache" -e CACHE_DIR=/data/cache `
    vuln-prio-ci python -m vuln_prio_ci run --cve CVE-2021-44228

docker run --rm -v "${PWD}:/work" -w /work -e CACHE_DIR=/work/cache `
    vuln-prio-ci python -m vuln_prio_ci run --gitlab-csv examples/cve-inventory.csv --cve-only --output prioritization.json
```

In the last example the repository is mounted at `/work` and is the working directory; paths are
relative to it, and `prioritization.json` ends up in the repository. `docker run` returns the exit
code of the run (PowerShell: `$LASTEXITCODE`), see [Result and exit code](#3-result-and-exit-code).

### Configuration

Configuration comes from environment variables, in the pipeline from CI/CD variables, locally
additionally from a `.env` file. The template is `.env.example`.

| Variable | Default | Meaning |
|---|---|---|
| `CACHE_DIR` | `./cache` | Location for `reference.sqlite`, KEV dump, mapping and manifest |
| `NVD_API_KEY` | empty | NVD key; speeds up retrieval (50 instead of 5 requests per 30 s) |
| `EPSS_THRESHOLD` | `0.088` | EPSS threshold for the evidence level |
| `CVSS_BAND_HIGH` | `7.0` | Lower bound of CVSS band C2 |
| `CVSS_BAND_CRITICAL` | `9.0` | Lower bound of CVSS band C3 |
| `EPSS_KEEP_SNAPSHOTS`, `EXPLOIT_KEEP_SNAPSHOTS` | `30` | snapshots kept per source; `0` = all |
| `METASPLOIT_MODULE_TYPES` | `exploit` | Module types that count as Metasploit evidence |

The source URLs are also listed in `.env.example`.

## Usage

### 1. Fetch reference data

Individual sources locally (stored in `CACHE_DIR`):

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

`all` fetches all sources at their latest state; `manifest` writes `bundle-manifest.json`. An
explicitly requested date (`--date`, `--ref`, `--as-of`) is pinned and exempt from retention. `unpin`
removes the pin again (commit SHA may be abbreviated) and applies retention immediately: if the
snapshot lies outside the most recent `*_KEEP_SNAPSHOTS`, it is deleted. NVD without `NVD_API_KEY`:
5 requests per 30 s, a full retrieval takes about a quarter of an hour; afterwards the sync runs
incrementally.

### 2. Prioritize findings

```
python -m vuln_prio_ci run --report-dir . --assessments security/prioritization-assessments.yaml \
    --max-age-days 2 --output prioritization.json --codequality gl-code-quality-report.json
```

| Option | Meaning |
|---|---|
| `--report FILE` | GitLab security report (may be repeated) |
| `--report-dir DIR` | Directory with `gl-sast-report.json`, `gl-dependency-scanning-report.json`, `gl-container-scanning-report.json` |
| `--gitlab-csv FILE` | CSV export of the Vulnerability Report (mode 2) |
| `--assessments FILE` | Assessment file (YAML) in the repository |
| `--output FILE` | Result file (JSON) |
| `--codequality FILE` | Code Quality report for `artifacts:reports:codequality` |
| `--max-age-days N` | Maximum age of the information bundle in days (default 2) |
| `--cve-only` | only findings with a CVE (method 1) |
| `--default-exposure` | Reachability if none is given (`remote`, `intern`, `lokal`; default `remote`) |
| `--online` | allow single EUVD lookups (default: off) |
| `--cve ID` | prioritize a single CVE (may be repeated), output in the terminal only |
| `--cvss-method` | only with `--cve`: decide solely by CVSS base score instead of method 1 |

Single CVEs without a report (method 1, CVSS base score from the NVD in the reference data store):

```
python -m vuln_prio_ci run --cve CVE-2021-44228 --cve CVE-2023-0464
```

The result appears in the terminal only: per CVE the level, rank, CVSS base score and rationale, also
for Planmäßig and Zurückgestellt. No files are created; `--cve` therefore cannot be combined with
`--report`, `--report-dir`, `--gitlab-csv`, `--output` or `--codequality`. The reference data
(step 1) must be present; the exit codes apply as below.

For comparison, `--cvss-method` decides the same CVEs solely by the CVSS base score
(`rules/decision_table_cvss.csv`, qualitative severity per CVSS v3/v4):

```
python -m vuln_prio_ci run --cve CVE-2021-44228 --cve CVE-2023-0464 --cvss-method
```

| CVSS severity | Base score | Level | Rank |
|---|---|---|---|
| critical | 9.0–10.0 | Sofort | 5 |
| high | 7.0–8.9 | Außerplanmäßig | 4 |
| medium | 4.0–6.9 | Planmäßig | 3 |
| low | 0.1–3.9 | Zurückgestellt | 2 |
| none | 0.0 | Zurückgestellt | 1 |

The CVSS method exists only in the terminal with `--cve`; reports and the CSV export are always
decided by method 1/2. A CVE without a CVSS base score is not prioritized but listed as "nicht
priorisiert" (not prioritized; exit code 3, unless another CVE is rated higher); the GitLab severity
does not count as a base score.

Two modes:

- **Mode 1**: findings of the pipeline run from the report artifacts (`--report-dir`).
- **Mode 2**: inventory of the main branch from the CSV export (`--gitlab-csv … --cve-only`).

The export is fetched by `python -m vuln_prio_ci export-inventory --project $CI_PROJECT_ID --output inventory.csv`
(Vulnerability Export API, Ultimate only; needs `GITLAB_API_TOKEN` with scope `read_api`).

**Test data:** `examples/cve-list.txt` contains 344 CVE identifiers (270 distinct; repeated entries
as in an inventory where one CVE affects several packages). `examples/cve-inventory.csv` is the same
list in the format of the CSV export, one row per entry, without package and CVSS vector. After
fetching the reference data (step 1):

```
python -m vuln_prio_ci run --gitlab-csv examples/cve-inventory.csv --cve-only --output prioritization.json
```

### 3. Result and exit code

| Exit code | Meaning | in the pipeline |
|---|---|---|
| 0 | no finding Sofort/Außerplanmäßig, all decided, bundle current | green |
| 3 | result limited: assessment missing or bundle older than `--max-age-days` | warning |
| 4 | at least one finding Außerplanmäßig | warning |
| 5 | at least one finding Sofort | warning |
| 1 | technical error: report missing/invalid, information bundle missing (for CVE findings), assessment file invalid, certifi outdated | failure |

Codes 3–5 are listed in `allow_failure:exit_codes`. With several conditions the highest code applies.
The log lists the findings of the levels Sofort and Außerplanmäßig with rationale and prints a
fill-in template for findings without an assessment. The Code Quality report shows the findings in the
merge request (Sofort → blocker, Außerplanmäßig → critical, Planmäßig → major, Zurückgestellt →
minor, without assessment → info).

### Assessment file

Findings without a CVE need an assessment by the development team (exploitation status, technical
impact, optionally reachability), as do VEX statements. The file lives in the product's repository,
usually at `security/prioritization-assessments.yaml`; an example is in
`examples/prioritization-assessments.yaml`.

Identifier of a finding in this file: without CVE `rule-ID:file`, with CVE `CVE:package`.

## Security notice: eMudhra/emSign incident (October 2026)

The intermediate certificates of eMudhra under the emSign root had insecure private keys. Anyone who
still trusts the root is open to man-in-the-middle attacks on TLS
([notes from the Python community](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576)).
**certifi ≥ 2026.10.19** and **pip ≥ 26.2.2** are patched. pip always loads its bundled certifi;
`--cert`, `PIP_CERT` or `REQUESTS_CA_BUNDLE` only add certificates and do not fix this. Only
updating pip helps.

Implementation in this project:
- **pip first, secured by hash:** The image, the test job and the instructions above upgrade pip to
  26.2.2 before any other installation, with a direct URL and `#sha256=…`. The hash protects the
  download even if the still-old pip trusts a wrong certificate while doing so.
- **Dependencies with hashes:** `pip install --require-hashes -r requirements.lock`. A substituted
  package aborts the installation.
- **certifi check at runtime:** `fetch-bundle`, `publish-bundle`, `export-inventory`,
  `run --online` and all retrievals under `python -m vuln_prio_ci.sources` abort with exit code 1 if
  certifi is older than 2026.10.19 (`src/vuln_prio_ci/tls.py`). The image build aborts as well.
- **Build the image without layer cache:** `docker build --pull --no-cache`, `ca-certificates` is
  updated in the image. A weekly scheduled pipeline (`PRIO_JOB=rebuild-image`) keeps the base image
  and system certificates current.
- **No dependency cooldown for certifi and pip:** With cooldowns you stay vulnerable until the update.
  On a new security release run `scripts/lock.py` immediately and adjust `PIP_WHEEL` (Dockerfile,
  `.gitlab-ci.yml`).

Python 3.15.1 ships pip 26.2.2 via `ensurepip`; under 3.15.0 a new venv still gets pip 26.2.1. The
first installation step is therefore mandatory for every new venv.

## Layout

```
vuln-prio-ci/
├── src/vuln_prio_ci/
│   ├── __main__.py            CLI: python -m vuln_prio_ci run|fetch-bundle|publish-bundle|export-inventory
│   ├── tls.py                 Minimum certifi version (eMudhra/emSign)
│   ├── config.py              Configuration (environment variables, locally .env)
│   ├── pipeline.py            Orchestration: identifier, VEX, enrichment, decision
│   ├── ci/                    run.py (run, exit codes), freshness.py (age of the information bundle),
│   │                          codequality.py (report for the merge request), gitlab_api.py
│   │                          (Generic Package Registry, Vulnerability Export API)
│   ├── ingest/                GitLab security reports, CSV export, assessment file
│   ├── normalize/             Identifier hierarchy CVE/EUVD/GHSA/CWE, fingerprint
│   ├── enrich/                CVSS, EPSS, KEV, Exploit-DB/Metasploit, NVD, EUVD (lookup only)
│   ├── decide/                Evidence level, protection need, rule tables, decision
│   ├── rules/                 decision_table_cve.csv (18 rows), decision_table_cveless.csv (54 rows),
│   │                          decision_table_cvss.csv (5 rows, only --cve --cvss-method)
│   ├── sources/               Fetching reference data: python -m vuln_prio_ci.sources <source>|all|manifest
│   ├── store/                 Reference data store (SQLite, CACHE_DIR/reference.sqlite)
│   └── models/                Pydantic schemas and enums
├── doc/                       Documentation of the data collection per script in src/vuln_prio_ci/sources
├── templates/prioritize.gitlab-ci.yml   Template for inclusion in product pipelines
├── examples/                  product.gitlab-ci.yml, prioritization-assessments.yaml,
│                              cve-list.txt + cve-inventory.csv (test data)
├── .gitlab-ci.yml             own pipeline: tests, image, daily information bundle
├── Dockerfile                 Image for the jobs (no service, no port)
├── requirements*.txt          Lower bounds; requirements*.lock: pinned versions with hashes
├── scripts/lock.py            generates the lock files
└── tests/
```

## Information bundle

The prioritization run calls no external services. The information comes from a daily generated
information bundle. This project's scheduled pipeline (`PRIO_JOB=reference-bundle`) fetches all
sources and publishes the bundle in this project's Generic Package Registry
(`reference-bundle/<timestamp>/reference-bundle.tar.gz`):

```
python -m vuln_prio_ci.sources all
python -m vuln_prio_ci publish-bundle --project "$CI_PROJECT_ID"
```

The product job downloads the latest version with the job token:

```
python -m vuln_prio_ci fetch-bundle --project <ID or path of vuln-prio-ci>
```

For this, vuln-prio-ci must list the product projects in its job token allowlist
(Settings > CI/CD > Job token permissions).

How the data is collected per source is described in [doc/](doc/README.md).

## Integration into the product pipeline

- Include `templates/prioritize.gitlab-ci.yml` via `include: project/file`, two jobs:
  - `vuln-prioritize` (mode 1): findings of the run from the report artifacts of SAST, Dependency
    Scanning and Container Scanning, assessment file from the repository.
  - `vuln-prioritize-inventory` (mode 2): scheduled (`PRIO_INVENTORY=true`), exports the main
    branch inventory via the Vulnerability Export API (`GITLAB_API_TOKEN`, scope `read_api`) and
    re-prioritizes the findings with a CVE (`--cve-only`).
- `examples/product.gitlab-ci.yml` shows a product. **Important:** The GitLab templates for SAST and
  Dependency Scanning store their reports only under `artifacts:reports`; downstream jobs then do not
  receive them (https://gitlab.com/gitlab-org/gitlab/-/issues/243717). The scanner jobs must be
  extended with `artifacts:paths`.
- `examples/prioritization-assessments.yaml`: assessment file (method 2 and VEX statements),
  located in the product at `security/prioritization-assessments.yaml`.

## Pinning dependencies

`requirements.txt`/`requirements-dev.txt` contain lower bounds, the lock files pinned versions with
SHA-256 for Linux x86_64 and CPython 3.15. Regenerate after every change to the lower bounds and on
security releases (needs pip ≥ 26.2.2):

```
python scripts/lock.py
```

The dependencies are `pydantic`, `pydantic-settings`, `httpx`, `ruamel.yaml` (pure Python, safe
loader; duplicate keys in the assessment file are an error) and `certifi`.

## Verified

- 194 tests under Python 3.15 (Windows), also with deprecation warnings as errors.
- Lock files resolved against PyPI (all packages available as wheels for cp315/manylinux).

Not verified: image build, run in a real GitLab instance, real report from the deployed Dependency
Scanning analyzer, NVD against the real API.
