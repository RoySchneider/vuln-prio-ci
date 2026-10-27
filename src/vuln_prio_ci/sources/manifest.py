"""Describe the state of the reference data (signal bundle): bundle-manifest.json.

The manifest records when the bundle was created and the state of each source. The CI command
uses it to check the maximum age (ci/freshness.py); the result of every prioritisation also
carries the state in `decision_note`.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .. import store
from ..store import epss as epss_store
from ..store import exploits as exploit_store
from ..store import nvd as nvd_store

MANIFEST_NAME = "bundle-manifest.json"
KEV_NAME = "kev-dump.json"


def describe(cache_dir: Path | str) -> dict:
    """Describe the state of each source in the cache directory (without the bundle creation time).

    Parameters
    ----------
    cache_dir : Path or str
        Cache directory containing ``reference.sqlite`` and the KEV dump.

    Returns
    -------
    dict
        State per source, keyed ``epss``, ``exploitdb``, ``metasploit``,
        ``nvd`` and ``kev``. The value is None if the source has not been
        fetched yet.
    """
    cache_dir = Path(cache_dir)
    db_path = cache_dir / "reference.sqlite"
    sources: dict = {}
    if db_path.exists():
        conn = store.connect(db_path)
        try:
            snap = epss_store.get_snapshot(conn)
            sources["epss"] = None if snap is None else {
                "score_date": snap.score_date.isoformat(), "model_version": snap.model_version,
                "fetched_at": snap.fetched_at, "rows": snap.row_count,
            }
            for source in (exploit_store.EXPLOITDB, exploit_store.METASPLOIT):
                s = exploit_store.get_snapshot(conn, source)
                sources[source] = None if s is None else {
                    "commit": s.commit_sha, "committed_at": s.committed_at, "fetched_at": s.fetched_at,
                    "references": s.ref_count,
                }
            sync = nvd_store.get_sync(conn)
            sources["nvd"] = None if sync is None else {
                "synced_until": sync.synced_until, "fetched_at": sync.fetched_at,
                "full_load": sync.full_load, "rows": nvd_store.count(conn),
            }
        finally:
            conn.close()
    kev_path = cache_dir / KEV_NAME
    if kev_path.exists():
        try:
            entries = json.loads(kev_path.read_text(encoding="utf-8"))
        except ValueError:
            entries = []
        mtime = datetime.fromtimestamp(kev_path.stat().st_mtime, tz=timezone.utc)
        sources["kev"] = {
            "fetched_at": mtime.isoformat(timespec="seconds"),
            "entries": len(entries) if isinstance(entries, list) else None,
            "latest_date_added": max((e.get("dateAdded") or "" for e in entries if isinstance(e, dict)),
                                     default=None) if isinstance(entries, list) else None,
        }
    else:
        sources["kev"] = None
    return sources


def write(cache_dir: Path | str, created_at: Optional[datetime] = None) -> Path:
    """Write the manifest into the cache directory.

    Parameters
    ----------
    cache_dir : Path or str
        Cache directory; the manifest is written to ``bundle-manifest.json``
        in it.
    created_at : datetime, optional
        Creation time of the bundle. Defaults to the current time.

    Returns
    -------
    Path
        Path of the written manifest.
    """
    cache_dir = Path(cache_dir)
    created = (created_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    manifest = {"created_at": created.isoformat(timespec="seconds"), "sources": describe(cache_dir)}
    path = cache_dir / MANIFEST_NAME
    path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def read(cache_dir: Path | str) -> Optional[dict]:
    """Read the manifest from the cache directory.

    Parameters
    ----------
    cache_dir : Path or str
        Cache directory containing ``bundle-manifest.json``.

    Returns
    -------
    dict or None
        The parsed manifest, or None if it does not exist or is not valid JSON.
    """
    path = Path(cache_dir) / MANIFEST_NAME
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return None
