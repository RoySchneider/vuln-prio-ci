# `manifest.py` – state of the information bundle

This script does not collect external data. It describes the state of the retrieved sources in the
cache directory and records it in `bundle-manifest.json`.

## Purpose

The CI command checks the maximum age of the bundle against the manifest (`ci/freshness.py`). The
manifest is written only after all sources have been retrieved successfully.

## `describe(cache_dir)`

Reads the state of each source from the cache directory. If an entry is empty (`None`), the source
has not been retrieved yet.

| Key | Origin | Content |
| --- | --- | --- |
| `epss` | most recent EPSS snapshot in `reference.sqlite` | retrieval date, model version, time of retrieval, row count |
| `exploitdb` | most recent Exploit-DB snapshot | commit, commit time, time of retrieval, references |
| `metasploit` | most recent Metasploit snapshot | as for Exploit-DB |
| `nvd` | sync state in `reference.sqlite` | `synced_until`, time of retrieval, full retrieval, row count |
| `kev` | file `kev-dump.json` | modification time of the file as time of retrieval, number of entries, most recent `dateAdded` |

If `reference.sqlite` does not exist, EPSS, Exploit-DB, Metasploit and NVD remain empty. If
`kev-dump.json` is unreadable, it is treated as an empty list.

## `write(cache_dir, created_at=None)`

Writes `bundle-manifest.json` to the cache directory:

```json
{
  "created_at": "2026-10-23T06:00:00+00:00",
  "sources": { "epss": {…}, "exploitdb": {…}, "metasploit": {…}, "nvd": {…}, "kev": {…} }
}
```

`created_at` is the creation time of the bundle (default: now, UTC).

## `read(cache_dir)`

Reads the manifest. If the file is missing or not valid JSON, the function returns `None`.
