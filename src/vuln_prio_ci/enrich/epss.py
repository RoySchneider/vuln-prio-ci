"""[3] EPSS lookup against the local reference data store.

EPSS provides the 30-day exploitation forecast (FIRST). It is keyed by CVE and not available in
the CVE-less case. The daily files are fetched separately (sources/epss.py); there is no network
call here. All values of a run come from the same snapshot, whose model version and score date are
carried in the result.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import date
from pathlib import Path
from typing import Optional

from .. import store
from ..store import epss as epss_store

log = logging.getLogger(__name__)


class EpssLookup:
    """Read access to an EPSS snapshot for the duration of a prioritisation run.

    Can be used as a context manager, which closes the connection on exit.

    Parameters
    ----------
    conn : sqlite3.Connection
        Open connection to the reference data store.
    snapshot : epss_store.Snapshot or None
        The snapshot to read from, or None if none is stored.

    Attributes
    ----------
    snapshot : epss_store.Snapshot or None
        The snapshot all values come from.
    """

    def __init__(self, conn: sqlite3.Connection, snapshot: Optional[epss_store.Snapshot]):
        self._conn = conn
        self.snapshot = snapshot

    def score(self, cve_id: str) -> Optional[tuple[float, Optional[float]]]:
        """Return the EPSS score and percentile of a CVE.

        Parameters
        ----------
        cve_id : str
            CVE ID to look up.

        Returns
        -------
        tuple[float, Optional[float]] or None
            ``(epss, percentile)``, or None if there is no snapshot or the CVE
            is missing from it.
        """
        if self.snapshot is None:
            return None
        return epss_store.get_score(self._conn, self.snapshot.score_date, cve_id)

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()

    def __enter__(self) -> EpssLookup:
        """Return the lookup itself when entering a ``with`` block."""
        return self

    def __exit__(self, *exc) -> None:
        """Close the connection when leaving a ``with`` block."""
        self.close()


def open_lookup(as_of: Optional[date] = None, db_path: Optional[Path | str] = None) -> EpssLookup:
    """Open the latest snapshot; with `as_of`, the latest up to that date.

    A warning is logged if no snapshot exists; EPSS values then stay unknown.

    Parameters
    ----------
    as_of : date, optional
        Only snapshots with a score date on or before this day are considered.
    db_path : Path or str, optional
        Location of the SQLite file. Defaults to the configured cache
        directory.

    Returns
    -------
    EpssLookup
        Lookup bound to the selected snapshot. The caller closes it.
    """
    conn = store.connect(db_path)
    snapshot = epss_store.get_snapshot(conn, as_of)
    if snapshot is None:
        log.warning("kein EPSS-Snapshot vorhanden, EPSS-Werte bleiben unbekannt (python -m vuln_prio_ci.sources epss)")
    return EpssLookup(conn, snapshot)
