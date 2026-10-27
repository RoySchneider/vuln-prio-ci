"""EPSS snapshots in the reference data store.

A snapshot is a daily EPSS file: score date, model version and origin (URL, SHA-256 of the
fetched file). The values of a finding always come from exactly one snapshot; if the CVE is
missing there, the EPSS value is unknown, with no fallback to older snapshots.

Retention: on fetch, only the most recent `keep` snapshots are kept. Snapshots fetched explicitly
for a given date are `pinned` and are retained (reference dates of the evaluation).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS epss_snapshot (
    score_date      TEXT PRIMARY KEY,     -- YYYY-MM-DD, score date of the values
    model_version   TEXT,                 -- NULL for older files without a comment line
    score_timestamp TEXT,                 -- timestamp from the comment line
    source_url      TEXT NOT NULL,
    sha256          TEXT NOT NULL,        -- checksum of the fetched .csv.gz
    row_count       INTEGER NOT NULL,
    fetched_at      TEXT NOT NULL,        -- ISO-8601, UTC
    pinned          INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS epss_score (
    score_date  TEXT NOT NULL,
    cve         TEXT NOT NULL,
    epss        REAL NOT NULL,
    percentile  REAL,                     -- NULL for files without a percentile column
    PRIMARY KEY (score_date, cve)
) WITHOUT ROWID;
"""

_SNAPSHOT_COLUMNS = "score_date, model_version, score_timestamp, source_url, sha256, row_count, fetched_at, pinned"


@dataclass(frozen=True)
class Snapshot:
    score_date: date
    model_version: Optional[str]
    score_timestamp: Optional[str]
    source_url: str
    sha256: str
    row_count: int
    fetched_at: str
    pinned: bool = False


def save_snapshot(
    conn: sqlite3.Connection,
    snapshot: Snapshot,
    rows: Sequence[tuple[str, float, Optional[float]]],
) -> None:
    """Replace the snapshot of the score date completely (one transaction, all or nothing).

    Existing scores of the date are deleted and `rows` is inserted in their
    place. The snapshot row is inserted or updated; an existing pin is never
    cleared.

    Parameters
    ----------
    conn : sqlite3.Connection
        Open connection to the database containing the EPSS tables.
    snapshot : Snapshot
        Snapshot metadata. ``score_date`` identifies the snapshot.
    rows : Sequence[tuple[str, float, Optional[float]]]
        Scores as ``(cve, epss, percentile)``. The CVE ID is stored in upper
        case; the percentile may be None.
    """
    day = snapshot.score_date.isoformat()
    with conn:
        conn.execute("DELETE FROM epss_score WHERE score_date = ?", (day,))
        conn.executemany(
            "INSERT INTO epss_score (score_date, cve, epss, percentile) VALUES (?, ?, ?, ?)",
            ((day, cve.upper(), score, percentile) for cve, score, percentile in rows),
        )
        conn.execute(
            f"""INSERT INTO epss_snapshot ({_SNAPSHOT_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(score_date) DO UPDATE SET
                    model_version = excluded.model_version,
                    score_timestamp = excluded.score_timestamp,
                    source_url = excluded.source_url,
                    sha256 = excluded.sha256,
                    row_count = excluded.row_count,
                    fetched_at = excluded.fetched_at,
                    pinned = MAX(pinned, excluded.pinned)""",
            (
                day,
                snapshot.model_version,
                snapshot.score_timestamp,
                snapshot.source_url,
                snapshot.sha256,
                snapshot.row_count,
                snapshot.fetched_at,
                int(snapshot.pinned),
            ),
        )


def pin(conn: sqlite3.Connection, score_date: date) -> None:
    """Pin a snapshot so that `prune` does not remove it.

    Parameters
    ----------
    conn : sqlite3.Connection
        Open connection to the database containing the EPSS tables.
    score_date : date
        Score date of the snapshot to pin.
    """
    with conn:
        conn.execute("UPDATE epss_snapshot SET pinned = 1 WHERE score_date = ?", (score_date.isoformat(),))


def unpin(conn: sqlite3.Connection, score_date: date) -> bool:
    """Remove the pin of a snapshot so that `prune` treats it like any other snapshot.

    Parameters
    ----------
    conn : sqlite3.Connection
        Open connection to the database containing the EPSS tables.
    score_date : date
        Score date of the snapshot to unpin.

    Returns
    -------
    bool
        True if a snapshot with that score date exists, False otherwise.
    """
    with conn:
        cur = conn.execute("UPDATE epss_snapshot SET pinned = 0 WHERE score_date = ?", (score_date.isoformat(),))
    return cur.rowcount > 0


def get_snapshot(conn: sqlite3.Connection, as_of: Optional[date] = None) -> Optional[Snapshot]:
    """Return the latest snapshot; with `as_of`, the latest with a score date <= `as_of`.

    Parameters
    ----------
    conn : sqlite3.Connection
        Open connection to the database containing the EPSS tables.
    as_of : date, optional
        If given, only snapshots with a score date on or before this day are
        considered. Defaults to the latest snapshot overall.

    Returns
    -------
    Snapshot or None
        The matching snapshot, or None if there is none.
    """
    if as_of is None:
        row = conn.execute(
            f"SELECT {_SNAPSHOT_COLUMNS} FROM epss_snapshot ORDER BY score_date DESC LIMIT 1"
        ).fetchone()
    else:
        row = conn.execute(
            f"SELECT {_SNAPSHOT_COLUMNS} FROM epss_snapshot WHERE score_date <= ? ORDER BY score_date DESC LIMIT 1",
            (as_of.isoformat(),),
        ).fetchone()
    return _to_snapshot(row)


def get_snapshot_for_date(conn: sqlite3.Connection, score_date: date) -> Optional[Snapshot]:
    """Return the snapshot with exactly the given score date.

    Parameters
    ----------
    conn : sqlite3.Connection
        Open connection to the database containing the EPSS tables.
    score_date : date
        Score date of the snapshot.

    Returns
    -------
    Snapshot or None
        The snapshot, or None if that date has not been stored.
    """
    row =conn.execute(
        f"SELECT {_SNAPSHOT_COLUMNS} FROM epss_snapshot WHERE score_date = ?", (score_date.isoformat(),)
    ).fetchone()
    return _to_snapshot(row)


def get_score(conn: sqlite3.Connection, score_date: date, cve_id: str) -> Optional[tuple[float, Optional[float]]]:
    """Return the EPSS score and percentile of the CVE in the snapshot of the score date.

    Parameters
    ----------
    conn : sqlite3.Connection
        Open connection to the database containing the EPSS tables.
    score_date : date
        Score date of the snapshot to read from. No fallback to other
        snapshots is made.
    cve_id : str
        CVE ID to look up; matching is case-insensitive.

    Returns
    -------
    tuple[float, Optional[float]] or None
        ``(epss, percentile)``, where the percentile may be None, or None if
        the CVE is not in that snapshot.
    """
    row = conn.execute(
        "SELECT epss, percentile FROM epss_score WHERE score_date = ? AND cve = ?",
        (score_date.isoformat(), cve_id.upper()),
    ).fetchone()
    return (row[0], row[1]) if row else None


def prune(conn: sqlite3.Connection, keep: int) -> list[date]:
    """Remove unpinned snapshots beyond the most recent `keep`. If keep <= 0, nothing is removed.

    Snapshots and their scores are deleted in one transaction. Pinned
    snapshots are never removed and do not count towards `keep`.

    Parameters
    ----------
    conn : sqlite3.Connection
        Open connection to the database containing the EPSS tables.
    keep : int
        Number of most recent unpinned snapshots to keep.

    Returns
    -------
    list[date]
        Score dates of the removed snapshots.
    """
    if keep <= 0:
        return []
    stale = [
        r[0]
        for r in conn.execute(
            "SELECT score_date FROM epss_snapshot WHERE pinned = 0 ORDER BY score_date DESC LIMIT -1 OFFSET ?",
            (keep,),
        )
    ]
    with conn:
        for day in stale:
            conn.execute("DELETE FROM epss_score WHERE score_date = ?", (day,))
            conn.execute("DELETE FROM epss_snapshot WHERE score_date = ?", (day,))
    return [date.fromisoformat(d) for d in stale]


def _to_snapshot(row: Optional[tuple]) -> Optional[Snapshot]:
    """Convert a row of ``epss_snapshot`` into a `Snapshot`.

    Parameters
    ----------
    row : tuple or None
        Row in the column order of ``_SNAPSHOT_COLUMNS``, or None.

    Returns
    -------
    Snapshot or None
        The snapshot with the date parsed and ``pinned`` as bool, or None if
        `row` is None.
    """
    if row is None:
        return None
    score_date, model_version, score_timestamp, source_url, sha256, row_count, fetched_at, pinned = row
    return Snapshot(
        score_date=date.fromisoformat(score_date),
        model_version=model_version,
        score_timestamp=score_timestamp,
        source_url=source_url,
        sha256=sha256,
        row_count=row_count,
        fetched_at=fetched_at,
        pinned=bool(pinned),
    )
