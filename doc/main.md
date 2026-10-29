# `__main__.py` – command line for retrieval

`python -m vuln_prio_ci.sources <source>` triggers the retrieval scripts, manually or on a schedule.

## Commands

| Command | Effect |
| --- | --- |
| `epss` | fetch the most recent EPSS daily file |
| `epss --date YYYY-MM-DD` | fetch the daily file of a cutoff date (is pinned) |
| `exploitdb [--ref SHA]` | Exploit-DB: branch `main` or the given commit (pinned) |
| `metasploit [--ref SHA]` | Metasploit: branch `master` or the given commit (pinned) |
| `exploitdb`/`metasploit` `--as-of YYYY-MM-DD` | last commit up to the end of the cutoff date (pinned), for the evaluation at observation time T |
| `kev` | load the KEV dump (cumulative, no snapshot and no pin needed) |
| `nvd [--full]` | CVSS base scores from the NVD, incremental or full |
| `all` | all sources at their most recent state (for the schedule) |
| `manifest` | write `bundle-manifest.json` to `CACHE_DIR` |
| `unpin epss YYYY-MM-DD` | remove the pin of an EPSS snapshot, then apply retention |
| `unpin exploitdb`/`metasploit SHA` | remove the pin of an exploit snapshot (SHA may be abbreviated, must be unambiguous), then apply retention |

`--ref` and `--as-of` are mutually exclusive.

## Flow

1. **Manifest and unpinning**: `manifest` writes only the manifest and ends. `unpin` works only on
   `reference.sqlite` (without network access and without CA check) and ends with exit code 1 if the
   snapshot is unknown or the abbreviated SHA is ambiguous.
2. **Check the CA bundle**: Before any network access it is checked that the installed `certifi` is
   not older than 2026.10.19 (eMudhra/emSign incident, `tls.py`). If it is older, the command ends
   with an error message and exit code 1.
3. **Run the sources**: For `all` in this order: EPSS, Exploit-DB, Metasploit, KEV, NVD. The sources
   run independently of each other; if one fails, the others are still attempted. `manifest` is not
   part of `all` and is called separately.

## KEV dump

The KEV dump is not collected in `sources/` but via `enrich/kev.py::refresh`. It comes from the
endpoint `<euvd_base_url>/kev/dump` of the EUVD (ENISA), which combines CISA KEV and EU KEV. The file
is stored unchanged as `kev-dump.json` in the cache directory; if the download fails, that is a
retrieval error.

## Output and exit code

For each source a summary is printed, for example the number of CVEs or references, whether the
snapshot was stored or unchanged, and which snapshots were removed.

| Exit code | Meaning |
| --- | --- |
| `0` | all selected sources succeeded |
| `1` | at least one retrieval failed or the CA bundle is outdated |
