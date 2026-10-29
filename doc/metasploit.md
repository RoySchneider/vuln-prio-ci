# `metasploit.py` – Metasploit module metadata

## Source

The file `db/modules_metadata_base.json` in the GitHub repository `rapid7/metasploit-framework`. It
describes each module with type (`exploit`, `auxiliary`, `post`, `payload`, …) and a reference list.
The URLs come from the configuration (`metasploit_commit_url`, `metasploit_commits_until_url`,
`metasploit_file_url`).

**Note:** Commit resolution uses the GitHub API without authentication. A limit of 60 requests per
hour and IP address applies.

## Step 1: Resolve the commit (`resolve_commit`)

The branch (default `master`) or a given commit SHA is resolved via the GitHub API. From the JSON
response the SHA (`sha`) and the committer time (`commit.committer.date`) are read and converted to
UTC. If anything is missing, the retrieval aborts with `SourceError`.

### Cutoff date: `commit_before(day)`

As with Exploit-DB: The commit list of the branch `master` up to `<day>T23:59:59Z` is queried (one
entry, the most recent) and its SHA is returned. This serves the cutoff-date snapshots of the
evaluation (AP-9.1).

## Step 2: Load and parse the file (`parse`)

The file is loaded at this commit SHA (see [git_snapshot.md](git_snapshot.md)). It must be a JSON
object whose entries are the modules; otherwise the retrieval aborts. If a module has no type, the
retrieval aborts as well.

Per module:

1. The identifier (`entry_id`) is `fullname`, alternatively the key in the object.
2. In `references` only strings starting with `CVE` are considered.
3. Each is cleaned with `common.normalize_cve`. If that is not possible, it is **skipped and counted**
   (`skipped_count`).
4. One reference is created per pair (CVE, module); duplicates are merged.

Fields taken over for a reference:

| Field | Origin |
| --- | --- |
| `entry_id` | `fullname` or key |
| `entry_type` | `type` |
| `title` | `name` |
| `published` | `disclosure_date` |

All modules with a CVE reference are stored, regardless of type. Which types count as
`e2_metasploit` evidence is set by the setting `metasploit_module_types` (default: only `exploit`,
decision of 13.09.2026). Scanner and DoS modules under `auxiliary` do not make exploitation available
without development effort of their own.

## Step 3: Store

Via `git_snapshot.sync`. Without `ref` the most recent state of `master` is fetched and **not**
pinned; with `ref` that commit is fetched and **pinned**. The most recent `exploit_keep_snapshots`
(default 30) unpinned snapshots are retained.
