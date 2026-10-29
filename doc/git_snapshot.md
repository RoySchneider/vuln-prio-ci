# `git_snapshot.py` – shared flow for Git sources

Exploit-DB and Metasploit exist as a file in a Git repository. This script contains the flow that
both share (`sync`). The source-specific parts, namely resolving the commit and parsing the file, are
provided by `exploitdb.py` and `metasploit.py`.

## Data types

| Type | Meaning |
| --- | --- |
| `Commit` | commit SHA and commit time (UTC) |
| `ParseResult` | CVE references found and number of skipped entries |
| `SyncResult` | stored snapshot, whether it was newly stored, and the removed commits |

## Flow of `sync`

1. **Check whether the commit is already stored.** If so, nothing is loaded. If the snapshot is to be
   pinned, it is pinned; retention then applies. Result: `stored = False`.
2. **Load the file.** The URL template (`…/{ref}/…`) is filled with the **commit SHA**, not the
   branch name. This way content and stored commit are guaranteed to match, even if the branch moves
   on between resolution and download.
3. **Parse** with the source-specific function `parse`. If the file contains not a single CVE
   reference, the retrieval aborts with `SourceError`.
4. **Create snapshot** with source, commit SHA, commit time, URL after redirection, SHA-256 of the
   file, number of references, number of skipped entries, time of retrieval and pin.
5. **Store** snapshot and references in one transaction (all or nothing).
6. **Apply retention**: The most recent `keep` unpinned snapshots are kept.

## Result

Tables `exploit_snapshot` (one entry per source and commit) and `exploit_reference` (per snapshot the
CVE references with entry ID, type, title, publication date and `verified`). Storage is
**unfiltered**; which entry types count as evidence is decided only by the lookup
(`enrich/exploits.py`).
