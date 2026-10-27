"""[3] KEV lookup via the EUVD-consolidated KEV dump.

The EUVD KEV dump (/api/kev/dump) combines CISA KEV and EU KEV and provides cveId, euvdId,
dateAdded and sources per entry. One integration thus covers both KEV catalogues (implementation
plan sect. 5.3). The dump is cached locally and kept as an index over CVE and EUVD IDs for lookups.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import httpx

from ..config import get_settings

_TIMEOUT = httpx.Timeout(15.0)


def _cache_path() -> Path:
    """Return the path of the cached KEV dump."""
    return Path(get_settings().cache_dir) / "kev-dump.json"


def refresh() -> bool:
    """Download the KEV dump and store it in the cache.

    Returns
    -------
    bool
        True on success, False if the download failed.
    """
    url = f"{get_settings().euvd_base_url}/kev/dump"
    try:
        resp = httpx.get(url, headers={"accept": "application/json"}, timeout=_TIMEOUT)
        resp.raise_for_status()
    except httpx.HTTPError:
        return False
    path = _cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(resp.text, encoding="utf-8")
    return True


def load_index() -> dict[str, dict]:
    """Build an index over CVE and EUVD IDs from the cached dump.

    Returns
    -------
    dict[str, dict]
        Mapping from upper-case CVE or EUVD ID to the KEV entry. Empty if no
        dump is cached or it is not valid JSON.
    """
    path = _cache_path()
    if not path.exists():
        return {}
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return {}
    index: dict[str, dict] = {}
    for entry in entries:
        for key in (entry.get("cveId"), entry.get("euvdId")):
            if key:
                index[key.upper()] = entry
    return index


def lookup(index: dict[str, dict], cve_id: Optional[str], euvd_id: Optional[str] = None) -> Optional[dict]:
    """Look up a KEV entry by CVE ID, then by EUVD ID.

    Parameters
    ----------
    index : dict[str, dict]
        Index as returned by `load_index`.
    cve_id : str or None
        CVE ID to look up first.
    euvd_id : str, optional
        EUVD ID to try if the CVE ID is not found.

    Returns
    -------
    dict or None
        The KEV entry, or None if neither ID is listed.
    """
    for key in (cve_id, euvd_id):
        if key and key.upper() in index:
            return index[key.upper()]
    return None
