"""Fetch the Metasploit module metadata (`db/modules_metadata_base.json` in rapid7/metasploit-framework).

The file describes each module with its type (exploit, auxiliary, post, payload, ...) and a list of
references; CVE IDs appear there as `CVE-YYYY-NNNN`. All modules with a CVE reference are stored,
regardless of type. Which types count as evidence `e2_metasploit` is set by `METASPLOIT_MODULE_TYPES`
(default: `exploit` only, decision of 2026-09-13), since scanner and DoS modules under `auxiliary` do
not make exploitation available without development effort of one's own.

Note: commit resolution uses the GitHub API without authentication (60 requests per hour per IP).
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Optional
from urllib.parse import quote

from ..config import get_settings
from ..store.exploits import METASPLOIT, Reference
from . import common, git_snapshot

DEFAULT_REF = "master"


def resolve_commit(ref: str) -> git_snapshot.Commit:
    """Resolve a branch name or commit SHA to a commit.

    Parameters
    ----------
    ref : str
        Branch name or commit SHA in the Metasploit repository.

    Returns
    -------
    git_snapshot.Commit
        The commit SHA and its commit time in UTC.

    Raises
    ------
    common.SourceError
        If the reference cannot be resolved or the request fails.
    """
    url =get_settings().metasploit_commit_url.format(ref=quote(ref, safe=""))
    data = common.get_json(url)
    try:
        sha = data["sha"]
        committed = data["commit"]["committer"]["date"]
    except (KeyError, TypeError):
        raise common.SourceError(f"Commit {ref!r} nicht auflösbar über {url}") from None
    return git_snapshot.Commit(sha=sha, committed_at=common.utc_timestamp(committed))


def commit_before(day: date) -> str:
    """Return the SHA of the last commit on the main branch up to the end of `day` (UTC).

    Basis for the reference-date snapshots of the evaluation (AP-9.1): the state
    of the source at the observation time T, not today's.

    Parameters
    ----------
    day : date
        Reference date; commits up to 23:59:59 UTC of this day are considered.

    Returns
    -------
    str
        Commit SHA.

    Raises
    ------
    common.SourceError
        If there is no commit up to that time or the request fails.
    """
    until = f"{day.isoformat()}T23:59:59Z"
    url = get_settings().metasploit_commits_until_url.format(branch=DEFAULT_REF, until=until)
    data = common.get_json(url)
    entry = data[0] if isinstance(data, list) and data else None
    sha = entry.get("sha") if isinstance(entry, dict) else None
    if not sha:
        raise common.SourceError(f"kein Commit bis {until} über {url}")
    return sha


def parse(payload: bytes) -> git_snapshot.ParseResult:
    """Parse `modules_metadata_base.json` into CVE references.

    Duplicate (CVE, module) pairs are merged. CVE values that cannot be
    cleaned up to a valid ID are skipped and counted.

    Parameters
    ----------
    payload : bytes
        Raw JSON file content.

    Returns
    -------
    git_snapshot.ParseResult
        The references and the number of skipped CVE values.

    Raises
    ------
    common.SourceError
        If the file is not valid JSON, is not an object of modules, or a
        module has no type.
    """
    try:
        modules = json.loads(payload)
    except ValueError as exc:
        raise common.SourceError(f"modules_metadata_base.json nicht lesbar: {exc}") from exc
    if not isinstance(modules, dict):
        raise common.SourceError("modules_metadata_base.json: Objekt mit Modulen erwartet")

    refs: dict[tuple[str, str], Reference] = {}
    skipped = 0
    for key, module in modules.items():
        if not isinstance(module, dict) or not module.get("type"):
            raise common.SourceError(f"modules_metadata_base.json: Modul {key!r} ohne Typ")
        entry_id = module.get("fullname") or key
        for reference in module.get("references") or []:
            if not isinstance(reference, str) or not reference.strip().upper().startswith("CVE"):
                continue
            cve = common.normalize_cve(reference)
            if cve is None:
                skipped += 1
                continue
            refs.setdefault((cve, entry_id), Reference(
                cve=cve,
                entry_id=entry_id,
                entry_type=module["type"],
                title=module.get("name") or None,
                published=module.get("disclosure_date") or None,
            ))
    return git_snapshot.ParseResult(refs=list(refs.values()), skipped=skipped)


def sync(ref: Optional[str] = None, *, db_path: Optional[Path | str] = None, keep: Optional[int] = None) -> git_snapshot.SyncResult:
    """Fetch the state of the branch `master` or, with `ref`, of a specific commit (which is pinned).

    Parameters
    ----------
    ref : str, optional
        Commit SHA to fetch. Defaults to the latest state of ``master``.
    db_path : Path or str, optional
        Location of the SQLite file. Defaults to the configured cache
        directory.
    keep : int, optional
        Number of most recent unpinned snapshots to keep. Defaults to the
        configured ``exploit_keep_snapshots``.

    Returns
    -------
    git_snapshot.SyncResult
        The snapshot, whether it was newly stored, and the pruned commits.
    """
    settings = get_settings()
    commit = resolve_commit(ref or DEFAULT_REF)
    return git_snapshot.sync(
        METASPLOIT,
        commit,
        settings.metasploit_file_url,
        parse,
        pinned=ref is not None,
        keep=settings.exploit_keep_snapshots if keep is None else keep,
        db_path=db_path,
    )
