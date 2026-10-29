# `common.py`

This script does not collect any data itself. It provides the functions that all retrieval scripts use.

## HTTP download

- **`download(url)`** loads a file via `httpx.get` (redirects are followed, timeout 60 s) and returns
  the content and the URL after redirection. The latter is stored as the origin in the snapshot.
- **`get_json(url)`** uses `download` and reads the response as JSON.

Error handling: every error is reported as `SourceError`.

| Case | Message |
| --- | --- |
| network error | "Abruf fehlgeschlagen" (retrieval failed) |
| HTTP 403 or 404 | "nicht gefunden" (not found; EPSS answers a date without a file with 403) |
| other HTTP error status | "Abruf fehlgeschlagen (HTTP …)" |
| no valid JSON response | "keine gültige JSON-Antwort" (no valid JSON response) |

## CVE cleanup

**`normalize_cve(value)`** cleans up a CVE entry from free-text fields (Exploit-DB, Metasploit):

1. Remove all whitespace (`CVE-2015- 5698` becomes `CVE-2015-5698`).
2. Convert to upper case.
3. Strip trailing punctuation (`.`, `,`, `;`, `:`).
4. Check against the pattern `CVE-YYYY-NNNN…` (at least four digits at the end).

If the result does not match, the function returns `None`, for example for placeholders such as
`CVE-n/a`.

## Timestamps

- **`utc_timestamp(value)`** converts an ISO 8601 timestamp of any zone to UTC, accurate to the
  second. A trailing `Z` is accepted, a timestamp without a zone is treated as UTC. The result can be
  sorted as text.
- **`now_utc()`** returns the current time in the same format. It serves as `fetched_at` (time of
  retrieval).
