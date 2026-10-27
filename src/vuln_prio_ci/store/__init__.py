"""Local reference data store (SQLite) for externally sourced data.

EPSS and the other exploitation signals are public reference data. The service
keeps them as dated snapshots on the cache volume. Fetching (sources) and
lookup (enrich) are kept separate: there is no network call in the request path, and every
result can be traced back to a snapshot.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional

from ..config import get_settings
from . import epss, exploits, nvd


def default_path() -> Path:
    return Path(get_settings().cache_dir) / "reference.sqlite"


def connect(path: Optional[Path | str] = None) -> sqlite3.Connection:
    """Open the reference store and create any missing tables.

    The parent directory of the database file is created if necessary. The
    connection uses WAL journal mode so the service can read while a fetch
    run writes. The schemas of the EPSS, exploit and NVD tables are applied
    on every call.

    Parameters
    ----------
    path : Path or str, optional
        Location of the SQLite file. Defaults to ``reference.sqlite`` in the
        configured cache directory (see `default_path`)

    Returns
    -------
    sqlite3.Connection
        Open connection with all schemas applied. The caller is responsible
        for closing it
    """
    path = Path(path) if path is not None else default_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    # WAL: the service can read while a fetch run is writing
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(epss.SCHEMA)
    conn.executescript(exploits.SCHEMA)
    conn.executescript(nvd.SCHEMA)
    return conn
