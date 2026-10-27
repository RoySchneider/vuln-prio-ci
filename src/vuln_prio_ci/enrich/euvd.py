"""[3] EUVD integration (ENISA - European Union Vulnerability Database).

Three uses (implementation plan sect. 5.6):
- single lookup /api/enisaid?id=<CVE or EUVD ID>  -> CVSS, EPSS, aliases, product/vendor
- CVE<->EUVD mapping dump /api/dump/cve-euvd-mapping (CSV, daily 07:00 UTC) -> alias resolution
- KEV dump /api/kev/dump                          -> see kev.py

Unauthenticated GET. Dumps are cached locally (CACHE_DIR). Network errors are caught and treated
as "no result" (the service stays operational, the signal is then missing).
[open: rate-limit/caching policy, live field comparison against the official API]
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Optional

import httpx

from ..config import get_settings

_TIMEOUT = httpx.Timeout(10.0)


def lookup(identifier: Optional[str]) -> Optional[dict]:
    """Fetch a single EUVD record by CVE or EUVD ID.

    Parameters
    ----------
    identifier : str or None
        CVE or EUVD ID to look up.

    Returns
    -------
    dict or None
        The parsed JSON record, or None if `identifier` is empty, the request
        fails or the response is not valid JSON.
    """
    if not identifier:
        return None
    url = f"{get_settings().euvd_base_url}/enisaid"
    try:
        resp = httpx.get(url, params={"id": identifier}, headers={"accept": "application/json"}, timeout=_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except (httpx.HTTPError, ValueError):
        return None


def cve_for_euvd(euvd_id: str) -> Optional[str]:
    """Resolve an EUVD ID to a CVE via the cached mapping (identifier hierarchy level 2).

    Parameters
    ----------
    euvd_id : str
        EUVD ID; matching is case-insensitive.

    Returns
    -------
    str or None
        The CVE ID, or None if the ID is not in the mapping or no mapping is cached.
    """
    mapping = _load_mapping()
    return mapping.get(euvd_id.upper())


def _mapping_cache_path() -> Path:
    """Return the path of the cached CVE<->EUVD mapping file."""
    return Path(get_settings().cache_dir) / "cve-euvd-mapping.csv"


def refresh_mapping() -> bool:
    """Download the CVE<->EUVD mapping dump and store it in the cache.

    Returns
    -------
    bool
        True on success, False if the download failed.
    """
    url = f"{get_settings().euvd_base_url}/dump/cve-euvd-mapping"
    try:
        resp = httpx.get(url, timeout=_TIMEOUT)
        resp.raise_for_status()
    except httpx.HTTPError:
        return False
    path = _mapping_cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(resp.text, encoding="utf-8")
    return True


def _load_mapping() -> dict[str, str]:
    """Load the cached mapping file.

    Returns
    -------
    dict[str, str]
        Mapping from EUVD ID to CVE ID, both upper case. Empty if no mapping
        is cached.
    """
    path = _mapping_cache_path()
    if not path.exists():
        return {}
    mapping: dict[str, str] = {}
    for row in csv.reader(path.read_text(encoding="utf-8").splitlines()):
        if len(row) >= 2:
            euvd_id, cve_id = row[0].strip().upper(), row[1].strip().upper()
            mapping[euvd_id] = cve_id
    return mapping
