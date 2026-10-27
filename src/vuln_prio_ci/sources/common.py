"""Shared building blocks of the fetch modules: error class, HTTP download, CVE normalisation."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

_TIMEOUT = httpx.Timeout(60.0)
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


class SourceError(Exception):
    """Raised when fetching an external source fails or its content is unusable."""


def download(url: str) -> tuple[bytes, str]:
    """Download a file; return its content and the URL after redirects.

    Parameters
    ----------
    url : str
        URL to download. Redirects are followed.

    Returns
    -------
    content : bytes
        Raw response body.
    final_url : str
        URL of the response after all redirects.

    Raises
    ------
    SourceError
        If the request fails, or the server answers with an HTTP error
        status (403 and 404 are reported as "not found").
    """
    try:
        resp = httpx.get(url, follow_redirects=True, timeout=_TIMEOUT)
    except httpx.HTTPError as exc:
        raise SourceError(f"Abruf fehlgeschlagen: {url}: {exc}") from exc
    if resp.status_code in (403, 404):
        raise SourceError(f"nicht gefunden: {url} (HTTP {resp.status_code})")
    if resp.is_error:
        raise SourceError(f"Abruf fehlgeschlagen: {url} (HTTP {resp.status_code})")
    return resp.content, str(resp.url)


def get_json(url: str) -> Any:
    """Download a URL and parse the response as JSON.

    Parameters
    ----------
    url : str
        URL to download, see `download`.

    Returns
    -------
    Any
        The parsed JSON document.

    Raises
    ------
    SourceError
        If the download fails or the response is not valid JSON.
    """
    payload, _ = download(url)
    try:
        return json.loads(payload)
    except ValueError as exc:
        raise SourceError(f"keine gültige JSON-Antwort von {url}") from exc


def normalize_cve(value: str) -> Optional[str]:
    """Clean up a CVE value from a free-text field; None if no valid ID remains.

    Fixes the typos found in Exploit-DB/Metasploit (whitespace, trailing
    punctuation, lower case). Placeholders such as ``CVE-n/a`` yield None.

    Parameters
    ----------
    value : str
        Raw CVE value.

    Returns
    -------
    str or None
        The CVE ID in upper case, or None if it does not match
        ``CVE-YYYY-NNNN...`` after cleaning.
    """
    cve = re.sub(r"\s+", "", value).upper().rstrip(".,;:")
    return cve if CVE_PATTERN.match(cve) else None


def utc_timestamp(value: str) -> str:
    """Convert an ISO-8601 timestamp of any zone to UTC with second precision.

    The result is sortable as text.

    Parameters
    ----------
    value : str
        ISO-8601 timestamp. A trailing ``Z`` is accepted; a timestamp
        without a time zone is assumed to be UTC.

    Returns
    -------
    str
        The timestamp in UTC, truncated to seconds, with a ``+00:00`` offset.

    Raises
    ------
    SourceError
        If `value` is not a valid ISO-8601 timestamp.
    """
    try:
        text = value.strip()
        if text.endswith(("Z", "z")):   # fromisoformat only understands "Z" from Python 3.11
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    except (TypeError, ValueError) as exc:
        raise SourceError(f"ungültiger Zeitstempel {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")


def now_utc() -> str:
    """Return the current time in UTC.

    Returns
    -------
    str
        ISO-8601 timestamp with second precision and a ``+00:00`` offset.
    """
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
