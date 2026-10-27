"""Shared workflow for sources that are available as a file in a Git repository.

Resolve the commit -> if the commit is already stored, load nothing -> otherwise load the file at
exactly that commit, validate it, store it as a snapshot -> apply retention. The file is loaded by
commit SHA instead of by branch, so that the content and the stored commit are guaranteed to match.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .. import store
from ..store import exploits as exploit_store
from . import common

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Commit:
    """A Git commit of a source repository.

    Attributes
    ----------
    sha : str
        Commit SHA.
    committed_at : str
        Commit time as ISO-8601 timestamp in UTC.
    """

    sha: str
    committed_at: str   # ISO-8601, UTC


@dataclass(frozen=True)
class ParseResult:
    """Result of parsing a source file.

    Attributes
    ----------
    refs : list[exploit_store.Reference]
        CVE references found in the file.
    skipped : int
        Number of entries that could not be cleaned up to a valid CVE ID.
    """

    refs: list[exploit_store.Reference]
    skipped: int        # CVE entries that could not be cleaned up to a valid ID


@dataclass(frozen=True)
class SyncResult:
    """Outcome of `sync`.

    Attributes
    ----------
    snapshot : exploit_store.Snapshot
        The stored snapshot of the commit.
    stored : bool
        False if the commit was already stored and nothing was loaded.
    pruned : list[str]
        Commit SHAs of the snapshots removed by retention.
    """

    snapshot: exploit_store.Snapshot
    stored: bool        # False: commit was already stored
    pruned: list[str]


def sync(
    source: str,
    commit: Commit,
    file_url_template: str,
    parse: Callable[[bytes], ParseResult],
    *,
    pinned: bool,
    keep: int,
    db_path: Optional[Path | str] = None,
) -> SyncResult:
    """Store the file of a commit as a snapshot, unless the commit is already stored.

    Parameters
    ----------
    source : str
        Source name, ``'exploitdb'`` or ``'metasploit'``.
    commit : Commit
        Commit to store.
    file_url_template : str
        URL of the data file with a ``{ref}`` placeholder, filled with the
        commit SHA.
    parse : Callable[[bytes], ParseResult]
        Parser for the downloaded file content.
    pinned : bool
        Whether the snapshot is pinned and exempt from retention.
    keep : int
        Number of most recent unpinned snapshots to keep.
    db_path : Path or str, optional
        Location of the SQLite file. Defaults to the configured cache
        directory.

    Returns
    -------
    SyncResult
        The snapshot, whether it was newly stored, and the pruned commits.

    Raises
    ------
    common.SourceError
        If the download fails or the file contains no CVE references.
    """
    with closing(store.connect(db_path)) as conn:
        existing = exploit_store.get_snapshot_for_commit(conn, source, commit.sha)
        if existing is not None:
            if pinned:
                exploit_store.pin(conn, source, commit.sha)
            pruned = exploit_store.prune(conn, source, keep)
            log.info("%s %s: unverändert", source, commit.sha[:8])
            return SyncResult(snapshot=existing, stored=False, pruned=pruned)

        payload, source_url = common.download(file_url_template.format(ref=commit.sha))
        result = parse(payload)
        if not result.refs:
            raise common.SourceError(f"{source}: keine CVE-Referenzen in {source_url}")

        snapshot = exploit_store.Snapshot(
            source=source,
            commit_sha=commit.sha,
            committed_at=commit.committed_at,
            source_url=source_url,
            sha256=hashlib.sha256(payload).hexdigest(),
            ref_count=len(result.refs),
            skipped_count=result.skipped,
            fetched_at=common.now_utc(),
            pinned=pinned,
        )
        exploit_store.save_snapshot(conn, snapshot, result.refs)
        pruned = exploit_store.prune(conn, source, keep)

    log.info("%s %s: %d CVE-Referenzen gespeichert, %d unlesbare übersprungen",
             source, commit.sha[:8], len(result.refs), result.skipped)
    return SyncResult(snapshot=snapshot, stored=True, pruned=pruned)
