"""[4] CVSS base score from the NVD data of the reference data store (no network call).

Fetching runs separately (sources/nvd.py). If there is no entry for a CVE, the base score from
this source stays unknown; the pipeline then falls back to the vector from the report.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional

from .. import store
from ..store import nvd as nvd_store


class NvdLookup:
    """Read access to the NVD ratings for the duration of a prioritisation run.

    Can be used as a context manager, which closes the connection on exit.

    Parameters
    ----------
    conn : sqlite3.Connection
        Open connection to the reference data store.

    Attributes
    ----------
    sync_state : nvd_store.SyncState or None
        State of the last NVD synchronisation, None if never synced.
    """

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn
        self.sync_state = nvd_store.get_sync(conn)

    def cvss(self, cve_id: str) -> Optional[nvd_store.CvssRecord]:
        """Return the stored CVSS rating of a CVE.

        Parameters
        ----------
        cve_id : str
            CVE ID to look up.

        Returns
        -------
        nvd_store.CvssRecord or None
            The rating, or None if the CVE has no entry.
        """
        return nvd_store.get(self._conn, cve_id)

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()

    def __enter__(self) -> NvdLookup:
        """Return the lookup itself when entering a ``with`` block."""
        return self

    def __exit__(self, *exc) -> None:
        """Close the connection when leaving a ``with`` block."""
        self.close()


def open_lookup(db_path: Optional[Path | str] = None) -> NvdLookup:
    """Open the NVD lookup on the reference data store.

    Parameters
    ----------
    db_path : Path or str, optional
        Location of the SQLite file. Defaults to the configured cache
        directory.

    Returns
    -------
    NvdLookup
        Lookup bound to a new connection. The caller closes it.
    """
    return NvdLookup(store.connect(db_path))
