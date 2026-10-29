# Documentation: data collection in `src/vuln_prio_ci/sources`

The scripts in `src/vuln_prio_ci/sources/` fetch the external reference data that the prioritization
run looks up later. Retrieval runs **separately from the prioritization run**: the run itself calls
no external services, it only reads the local reference data store.

## Overview

| Script | Source | Content | Document |
| --- | --- | --- | --- |
| `common.py` | – | shared building blocks (HTTP download, CVE cleanup, timestamps) | [common.md](common.md) |
| `epss.py` | FIRST EPSS | daily exploitation probability per CVE | [epss.md](epss.md) |
| `git_snapshot.py` | – | shared flow for sources that live as a file in a Git repository | [git_snapshot.md](git_snapshot.md) |
| `exploitdb.py` | Exploit-DB (GitLab) | public exploits with CVE reference | [exploitdb.md](exploitdb.md) |
| `metasploit.py` | Metasploit (GitHub) | Metasploit modules with CVE reference | [metasploit.md](metasploit.md) |
| `nvd.py` | NVD CVE API 2.0 | CVSS base scores per CVE | [nvd.md](nvd.md) |
| `manifest.py` | – | state of the information bundle (`bundle-manifest.json`) | [manifest.md](manifest.md) |
| `__main__.py` | – | command line that triggers the retrievals | [main.md](main.md) |

The KEV dump is not collected in `sources/` but in `enrich/kev.py` (EUVD dump). It is invoked through
the same command line, though; see [main.md](main.md).

## Common principle

1. **Download**: A file or API page is loaded via HTTP (`common.download`, `common.get_json`).
2. **Validation**: The content is validated completely before anything is stored. An error discards
   the entire retrieval (`SourceError`) so that no half snapshot is created.
3. **Storage**: The result is stored in the SQLite file `reference.sqlite` in the cache directory
   (`CACHE_DIR`, default `./cache`), see `src/vuln_prio_ci/store/`. The database runs in WAL mode so
   that it can be read while a retrieval is writing.
4. **Retention**: For each source the most recent `keep` snapshots are retained. Snapshots fetched
   explicitly for a date or a commit are **pinned** (`pinned`) and never removed.
5. **Manifest**: Only afterwards is `bundle-manifest.json` written (`manifest.py`), which records the
   state of each source.

## Configuration

All URLs and retention limits are in `src/vuln_prio_ci/config.py` and can be overridden via
environment variables or `.env`.

| Setting | Default | Used by |
| --- | --- | --- |
| `epss_bulk_base_url` | `https://epss.empiricalsecurity.com` | `epss.py` |
| `epss_keep_snapshots` | `30` | `epss.py` |
| `exploitdb_commit_url`, `exploitdb_commits_until_url`, `exploitdb_file_url` | GitLab API and raw file respectively | `exploitdb.py` |
| `metasploit_commit_url`, `metasploit_commits_until_url`, `metasploit_file_url` | GitHub API and raw file respectively | `metasploit.py` |
| `exploit_keep_snapshots` | `30` | `exploitdb.py`, `metasploit.py` |
| `nvd_api_url` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | `nvd.py` |
| `nvd_api_key` | empty | `nvd.py` |
| `cache_dir` | `./cache` | all |

The value `0` for `*_keep_snapshots` means: remove nothing, keep all snapshots.
