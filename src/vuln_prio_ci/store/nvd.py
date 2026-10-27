"""CVSS base scores from the NVD in the reference data store.

Exactly one rating is kept per CVE: the one selected according to:
version 3.x preferred over 4.0, within a version the primary rating preferred over the secondary
one, see sources/nvd.py::select_metric

The state is tracked in `nvd_sync`: up to which NVD
modification time the table has been reconciled and when the last fetch ran.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS nvd_cvss (
    cve           TEXT PRIMARY KEY,
    base_score    REAL NOT NULL,
    vector        TEXT,
    version       TEXT NOT NULL,     -- 3.1, 3.0 or 4.0
    rating_type   TEXT NOT NULL,     -- Primary or Secondary
    source        TEXT,              -- rating authority according to the NVD
    last_modified TEXT,              -- modification time of the CVE record according to the NVD
    fetched_at    TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS nvd_sync (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    synced_until  TEXT NOT NULL,     -- end of the most recently reconciled modification window (UTC)
    fetched_at    TEXT NOT NULL,     -- time of the last successful fetch (UTC)
    full_load     INTEGER NOT NULL   -- 1 if the full data set has been loaded
);
"""


@dataclass(frozen=True)
class CvssRecord:
    cve: str
    base_score: float
    vector: Optional[str]
    version: str
    rating_type: str
    source: Optional[str]
    last_modified: Optional[str]
    fetched_at: str


@dataclass(frozen=True)
class SyncState:
    synced_until: str
    fetched_at: str
    full_load: bool


def upsert(conn: sqlite3.Connection, records: Iterable[CvssRecord], removed: Iterable[str] = ()) -> int:
    """Write CVSS ratings; `removed` are CVEs for which the NVD no longer holds a usable rating.

    Existing entries are updated via ``ON CONFLICT``, new ones are inserted.
    Insert/update and delete run in the same transaction.

    Parameters
    ----------
    conn : sqlite3.Connection
        Open connection to the database containing the ``nvd_cvss`` table
    records : Iterable[CvssRecord]
        Ratings to write. The CVE ID is stored in upper case
    removed : Iterable[str], optional
        CVE IDs whose rating is deleted (default: none)

    Returns
    -------
    int
        Number of ratings written (inserted or updated); deleted entries are
        not counted.
    """
    rows = [
        (r.cve.upper(), r.base_score, r.vector, r.version, r.rating_type, r.source, r.last_modified, r.fetched_at)
        for r in records
    ]
    with conn:
        conn.executemany(
            """INSERT INTO nvd_cvss (cve, base_score, vector, version, rating_type, source, last_modified, fetched_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(cve) DO UPDATE SET
                   base_score = excluded.base_score, vector = excluded.vector, version = excluded.version,
                   rating_type = excluded.rating_type, source = excluded.source,
                   last_modified = excluded.last_modified, fetched_at = excluded.fetched_at""",
            rows,
        )
        conn.executemany("DELETE FROM nvd_cvss WHERE cve = ?", ((c.upper(),) for c in removed))
    return len(rows)


def get(conn: sqlite3.Connection, cve_id: str) -> Optional[CvssRecord]:
    """Look up the stored rating for a single CVE.

    Parameters
    ----------
    conn : sqlite3.Connection
        Open connection to the database containing the ``nvd_cvss`` table.
    cve_id : str
        CVE ID to look up; matching is case-insensitive.

    Returns
    -------
    CvssRecord or None
        The stored rating, or None if the CVE has no entry.
    """
    row =conn.execute(
        "SELECT cve, base_score, vector, version, rating_type, source, last_modified, fetched_at "
        "FROM nvd_cvss WHERE cve = ?",
        (cve_id.upper(),),
    ).fetchone()
    return CvssRecord(*row) if row else None


def count(conn: sqlite3.Connection) -> int:
    """Count the stored ratings.

    Parameters
    ----------
    conn : sqlite3.Connection
        Open connection to the database containing the ``nvd_cvss`` table.

    Returns
    -------
    int
        Number of rows in ``nvd_cvss``.
    """
    return conn.execute("SELECT COUNT(*) FROM nvd_cvss").fetchone()[0]


def get_sync(conn: sqlite3.Connection) -> Optional[SyncState]:
    """Read the NVD synchronisation state.

    Parameters
    ----------
    conn : sqlite3.Connection
        Open connection to the database containing the ``nvd_sync`` table.

    Returns
    -------
    SyncState or None
        The current state, or None if no sync has been recorded yet.
    """
    row =conn.execute("SELECT synced_until, fetched_at, full_load FROM nvd_sync WHERE id = 1").fetchone()
    return SyncState(row[0], row[1], bool(row[2])) if row else None


def set_sync(conn: sqlite3.Connection, synced_until: str, fetched_at: str, full_load: bool) -> None:
    """Record the NVD synchronisation state.

    The state is a single row. Once ``full_load`` has been stored as true it
    stays true, so a later incremental sync does not reset it.

    Parameters
    ----------
    conn : sqlite3.Connection
        Open connection to the database containing the ``nvd_sync`` table.
    synced_until : str
        End of the most recently reconciled modification window (UTC).
    fetched_at : str
        Time of the last successful fetch (UTC).
    full_load : bool
        Whether this sync loaded the complete data set.
    """
    with conn:
        conn.execute(
            """INSERT INTO nvd_sync (id, synced_until, fetched_at, full_load) VALUES (1, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET synced_until = excluded.synced_until,
                   fetched_at = excluded.fetched_at, full_load = MAX(full_load, excluded.full_load)""",
            (synced_until, fetched_at, int(full_load)),
        )
