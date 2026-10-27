"""Fetch CVSS base scores from the NVD (CVE API 2.0) and store them in the reference data store.

Selection per CVE according to the rule in chapter 5 (application to a scan result): version 3.x
preferred over 4.0; within a version the primary rating preferred over the secondary one, for 3.x
version 3.1 preferred over 3.0. Ratings according to CVSS 2.0 are not taken over, because the CVSS
ranges of method 1 are defined for 3.x and 4.0; a CVE with only a 2.0 rating counts as having no
CVSS base score.

Fetching:
- first run (or --full): the complete data set, page by page (at most 2000 per request);
- afterwards incrementally via lastModStartDate/lastModEndDate from the last reconciliation, in
  windows of at most 120 days (API limit).
Without an API key the NVD allows 5 requests per 30 seconds, with a key 50. The fetch waits between
requests accordingly (6.1 s or 0.7 s). A full fetch without a key therefore takes about a quarter
of an hour; set NVD_API_KEY for the schedule.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

import httpx

from .. import store
from ..config import get_settings
from ..store import nvd as nvd_store
from .common import SourceError, now_utc, utc_timestamp

log = logging.getLogger(__name__)

PAGE_SIZE = 2000
MAX_WINDOW = timedelta(days=120)
OVERLAP = timedelta(hours=1)          # overlap so that no record is missed at a window boundary
_VERSION_KEYS = (("cvssMetricV31", 0), ("cvssMetricV30", 1), ("cvssMetricV40", 2))


@dataclass(frozen=True)
class SyncResult:
    """Outcome of `sync`.

    Attributes
    ----------
    updated : int
        Number of ratings written.
    removed : int
        Number of CVEs without a usable rating, whose stored rating was deleted.
    synced_until : str
        End of the reconciled window as ISO-8601 timestamp in UTC.
    full_load : bool
        Whether the complete data set was loaded.
    """

    updated: int
    removed: int
    synced_until: str
    full_load: bool


def select_metric(cve_item: dict) -> Optional[tuple[float, Optional[str], str, str, Optional[str]]]:
    """Return the rating to use as (base score, vector, version, rating type, source), or None.

    Version 3.x is preferred over 4.0, then the primary rating over the
    secondary one, then 3.1 over 3.0. CVSS 2.0 ratings are ignored.

    Parameters
    ----------
    cve_item : dict
        The ``cve`` object of a vulnerability from the NVD CVE API 2.0.

    Returns
    -------
    tuple[float, Optional[str], str, str, Optional[str]] or None
        ``(base_score, vector, version, rating_type, source)`` of the selected
        rating, or None if the CVE has no usable 3.x or 4.0 rating.
    """
    metrics = cve_item.get("metrics") or {}
    candidates = []
    for key, version_rank in _VERSION_KEYS:
        for entry in metrics.get(key) or []:
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            if score is None:
                continue
            rating_type = entry.get("type") or "Secondary"
            type_rank = 0 if rating_type == "Primary" else 1
            # 3.1 and 3.0 form one group (3.x); within the group, rank by rating type first
            group = 0 if version_rank in (0, 1) else 1
            candidates.append(((group, type_rank, version_rank), (
                float(score), data.get("vectorString"), str(data.get("version") or ""), rating_type,
                entry.get("source"),
            )))
    if not candidates:
        return None
    return min(candidates, key=lambda c: c[0])[1]


def _format(ts: datetime) -> str:
    """Format a timestamp for the NVD date parameters.

    Parameters
    ----------
    ts : datetime
        Timestamp with a time zone.

    Returns
    -------
    str
        The timestamp in UTC as ``YYYY-MM-DDTHH:MM:SS.000+00:00``.
    """
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def _default_fetch(params: dict) -> dict:
    """Request one page from the NVD CVE API.

    The API key from the settings is sent if configured.

    Parameters
    ----------
    params : dict
        Query parameters of the request.

    Returns
    -------
    dict
        The parsed JSON response.

    Raises
    ------
    SourceError
        If the request fails, the API answers with an error status, or the
        response is not valid JSON.
    """
    settings = get_settings()
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    try:
        resp = httpx.get(settings.nvd_api_url, params=params, headers=headers, timeout=httpx.Timeout(120.0))
    except httpx.HTTPError as exc:
        raise SourceError(f"NVD-Abruf fehlgeschlagen: {exc}") from exc
    if resp.is_error:
        raise SourceError(f"NVD-Abruf fehlgeschlagen (HTTP {resp.status_code})")
    try:
        return resp.json()
    except ValueError as exc:
        raise SourceError("NVD-Antwort ist kein gültiges JSON") from exc


def _pages(window: Optional[tuple[datetime, datetime]], fetch: Callable[[dict], dict],
           pause: float) -> Any:
    """Iterate over the result pages of a query.

    Parameters
    ----------
    window : tuple[datetime, datetime] or None
        Modification window ``(start, end)``, or None for the complete data set.
    fetch : Callable[[dict], dict]
        Function that requests one page for the given query parameters.
    pause : float
        Seconds to wait between requests.

    Yields
    ------
    list
        The ``vulnerabilities`` items of one page.
    """
    start_index = 0
    while True:
        params: dict = {"startIndex": start_index, "resultsPerPage": PAGE_SIZE}
        if window:
            params["lastModStartDate"], params["lastModEndDate"] = _format(window[0]), _format(window[1])
        page = fetch(params)
        items = page.get("vulnerabilities") or []
        yield items
        total = int(page.get("totalResults") or 0)
        start_index += int(page.get("resultsPerPage") or len(items) or PAGE_SIZE)
        if start_index >= total or not items:
            return
        time.sleep(pause)


def sync(full: bool = False, fetch: Optional[Callable[[dict], dict]] = None,
         now: Optional[datetime] = None, db_path=None) -> SyncResult:
    """Reconcile the table nvd_cvss with the NVD (fully or from the last reconciliation).

    Parameters
    ----------
    full : bool, optional
        Load the complete data set. Done anyway if no sync state exists yet.
    fetch : Callable[[dict], dict], optional
        Function that requests one page from the API. Defaults to a real
        request; any other function disables the pause between requests.
    now : datetime, optional
        Current time with a time zone. Defaults to the actual time.
    db_path : Path or str, optional
        Location of the SQLite file. Defaults to the configured cache
        directory.

    Returns
    -------
    SyncResult
        Counts of written and removed ratings and the end of the reconciled
        window.

    Raises
    ------
    SourceError
        If a request fails.
    """
    settings = get_settings()
    fetch = fetch or _default_fetch
    pause = 0.7 if settings.nvd_api_key else 6.1
    if fetch is not _default_fetch:
        pause = 0.0
    now = now or datetime.now(timezone.utc)
    conn = store.connect(db_path)
    try:
        state = nvd_store.get_sync(conn)
        windows: list[Optional[tuple[datetime, datetime]]]
        do_full = full or state is None
        if do_full:
            windows = [None]
        else:
            start = datetime.fromisoformat(utc_timestamp(state.synced_until)) - OVERLAP
            windows = []
            while start < now:
                end = min(start + MAX_WINDOW, now)
                windows.append((start, end))
                start = end
        updated = removed = 0
        fetched_at = now_utc()
        for window in windows:
            for items in _pages(window, fetch, pause):
                records, gone = [], []
                for item in items:
                    cve = item.get("cve") or {}
                    cve_id = cve.get("id")
                    if not cve_id:
                        continue
                    chosen = select_metric(cve)
                    if chosen is None:
                        gone.append(cve_id)
                        continue
                    score, vector, version, rating_type, source = chosen
                    records.append(nvd_store.CvssRecord(
                        cve=cve_id, base_score=score, vector=vector, version=version,
                        rating_type=rating_type, source=source, last_modified=cve.get("lastModified"),
                        fetched_at=fetched_at,
                    ))
                updated += nvd_store.upsert(conn, records, gone)
                removed += len(gone)
                log.info("NVD: %d Bewertungen übernommen", updated)
        synced_until = now.astimezone(timezone.utc).isoformat(timespec="seconds")
        nvd_store.set_sync(conn, synced_until, fetched_at, do_full)
        return SyncResult(updated=updated, removed=removed, synced_until=synced_until, full_load=do_full)
    finally:
        conn.close()
