# `epss.py` – EPSS daily files

## Source

The bulk files of FIRST EPSS:

```
<epss_bulk_base_url>/epss_scores-<YYYY-MM-DD>.csv.gz   file of a specific day
<epss_bulk_base_url>/epss_scores-current.csv.gz        redirect to the most recent daily file
```

One download per day replaces individual requests per CVE through the FIRST API. For a date without a
file the server answers with HTTP 403.

## Flow of `sync(day=None)`

1. **Download**: The file for the day `day` is loaded, without a value the most recent one
   (`-current`).
2. **Unpack**: Decompress gzip and read as UTF-8 (with or without BOM). If this fails, the retrieval
   aborts with `EpssSourceError`.
3. **Validate and parse** (`parse`): see below. The file is validated completely before anything is
   stored.
4. **Determine the retrieval date**: It comes from the comment line of the file. The date from the
   file name of the redirect must match it, otherwise the retrieval aborts. If the comment line is
   missing (older files), the date from the file name applies. If both are missing, the retrieval
   aborts.
5. **Create snapshot**: retrieval date, model version, timestamp, origin URL, SHA-256 of the retrieved
   file, row count, time of retrieval. `pinned` is set if a date was requested explicitly.
6. **Store**: The snapshot is written only if none exists for the date yet or the SHA-256 differs. If
   it is identical, at most the pin is added.
7. **Retention**: The most recent `epss_keep_snapshots` (default 30) unpinned snapshots are kept;
   older ones are removed.

## File format and validation (`parse`)

| Variant | Structure |
| --- | --- |
| current | comment line `#model_version:v2026.06.15,score_date:2026-09-12T12:00:22Z`, then header line `cve,epss,percentile` |
| older | header line `cve,epss,percentile` or only `cve,epss`, without a comment line (model version unknown) |

Checked per line:

- The header line is one of the two permitted ones (case-insensitive).
- The column count matches the header line. Empty lines are skipped.
- The CVE identifier has the pattern `CVE-YYYY-NNNN…` and is stored in upper case.
- EPSS value and percentile are numbers in the range 0 to 1 (NaN is rejected).
- The file contains at least one value.

**A faulty line discards the entire retrieval.** A half snapshot would silently make EPSS values
appear as unknown.

## Result

Tables `epss_snapshot` (one entry per retrieval date) and `epss_score` (CVE, EPSS, percentile per
retrieval date). All values of a prioritization run come from exactly one snapshot. If the CVE is
missing there, the EPSS value is unknown; older snapshots are not used as a fallback.
