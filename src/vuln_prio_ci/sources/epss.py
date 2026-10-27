"""Fetch the daily EPSS scores (FIRST EPSS) as a snapshot.

The source is the bulk file `<EPSS_BULK_BASE_URL>/epss_scores-<YYYY-MM-DD>.csv.gz` or `-current.csv.gz`
(redirecting to the latest daily file). One download per day replaces per-CVE calls to the FIRST API;
for a date without a file the server answers with 403.

File formats encountered:
- current: comment line `#model_version:v2026.06.15,score_date:2026-09-12T12:00:22Z`,
  then header line `cve,epss,percentile`
- older files: `cve,epss,percentile` or only `cve,epss`, each without a comment line
  (model version unknown, score date taken from the file name)

The file is validated completely before anything is stored. A single faulty line discards the whole
fetch; a partial snapshot would silently make EPSS scores appear as unknown.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import logging
import re
from contextlib import closing
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Optional

from .. import store
from ..config import get_settings
from ..store import epss as epss_store
from . import common

log = logging.getLogger(__name__)

_FILE_DATE = re.compile(r"epss_scores-(\d{4}-\d{2}-\d{2})\.csv\.gz$")
_HEADERS = (["cve", "epss", "percentile"], ["cve", "epss"])


class EpssSourceError(common.SourceError):
    """Raised when the content of the EPSS file is unusable."""


@dataclass(frozen=True)
class ParsedFile:
    """Parsed content of a daily EPSS file.

    Attributes
    ----------
    model_version : str or None
        EPSS model version from the comment line, None for older files.
    score_timestamp : str or None
        Timestamp from the comment line, None for older files.
    score_date : date or None
        Score date derived from the timestamp, None for older files.
    rows : list[tuple[str, float, Optional[float]]]
        Scores as ``(cve, epss, percentile)``; the percentile is None for
        files without a percentile column.
    """

    model_version: Optional[str]
    score_timestamp: Optional[str]
    score_date: Optional[date]
    rows: list[tuple[str, float, Optional[float]]] = field(repr=False)


@dataclass(frozen=True)
class SyncResult:
    """Outcome of `sync`.

    Attributes
    ----------
    snapshot : epss_store.Snapshot
        The snapshot that was fetched.
    stored : bool
        False if an identical snapshot was already stored.
    pruned : list[date]
        Score dates of the snapshots removed by retention.
    """

    snapshot: epss_store.Snapshot
    stored: bool                      # False: identical snapshot was already stored
    pruned: list[date]


def parse(text: str) -> ParsedFile:
    """Validate and split the decompressed content of a daily EPSS file.

    Parameters
    ----------
    text : str
        Decompressed file content, with an optional leading comment line.

    Returns
    -------
    ParsedFile
        Metadata from the comment line and the validated score rows.

    Raises
    ------
    EpssSourceError
        If the header is unexpected, a line has the wrong number of columns,
        a CVE ID or score is invalid, or the file contains no scores.
    """
    lines = text.splitlines()
    meta: dict[str, str] = {}
    offset = 1
    if lines and lines[0].startswith("#"):
        for part in lines[0][1:].split(","):
            key, sep, value = part.partition(":")
            if sep:
                meta[key.strip()] = value.strip()
        lines = lines[1:]
        offset = 2

    reader = csv.reader(lines)
    header = [h.strip().lower() for h in next(reader, [])]
    if header not in _HEADERS:
        raise EpssSourceError(f"unerwartete Kopfzeile: {header}")

    rows: list[tuple[str, float, Optional[float]]] = []
    for lineno, record in enumerate(reader, start=offset + 1):
        if not record:
            continue
        if len(record) != len(header):
            raise EpssSourceError(f"Zeile {lineno}: {len(record)} statt {len(header)} Spalten")
        cve = record[0].strip().upper()
        if not common.CVE_PATTERN.match(cve):
            raise EpssSourceError(f"Zeile {lineno}: ungültige CVE-Kennung {record[0]!r}")
        score = _probability(record[1], lineno)
        percentile = _probability(record[2], lineno) if len(header) == 3 else None
        rows.append((cve, score, percentile))
    if not rows:
        raise EpssSourceError("Datei enthält keine Werte")

    timestamp = meta.get("score_date")
    return ParsedFile(
        model_version=meta.get("model_version"),
        score_timestamp=timestamp,
        score_date=date.fromisoformat(timestamp[:10]) if timestamp else None,
        rows=rows,
    )


def sync(
    day: Optional[date] = None,
    *,
    db_path: Optional[Path | str] = None,
    keep: Optional[int] = None,
) -> SyncResult:
    """Fetch the daily file (`day`, otherwise the latest) and store it as a snapshot.

    An explicitly requested date is pinned and exempt from retention.

    Parameters
    ----------
    day : date, optional
        Score date to fetch. Defaults to the latest daily file.
    db_path : Path or str, optional
        Location of the SQLite file. Defaults to the configured cache
        directory.
    keep : int, optional
        Number of most recent unpinned snapshots to keep. Defaults to the
        configured ``epss_keep_snapshots``.

    Returns
    -------
    SyncResult
        The snapshot, whether it was stored, and the pruned score dates.

    Raises
    ------
    EpssSourceError
        If the file is unreadable or invalid, or its score date does not match
        the file date or cannot be determined.
    common.SourceError
        If the download fails.
    """
    settings = get_settings()
    name = f"epss_scores-{day.isoformat()}.csv.gz" if day else "epss_scores-current.csv.gz"
    payload, source_url = common.download(f"{settings.epss_bulk_base_url.rstrip('/')}/{name}")

    try:
        text = gzip.decompress(payload).decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise EpssSourceError(f"Datei nicht lesbar: {exc}") from exc
    parsed = parse(text)

    match = _FILE_DATE.search(source_url)
    file_date = date.fromisoformat(match.group(1)) if match else day
    if parsed.score_date and file_date and parsed.score_date != file_date:
        raise EpssSourceError(f"Bezugsdatum {parsed.score_date} passt nicht zur Datei vom {file_date}")
    score_date = parsed.score_date or file_date
    if score_date is None:
        raise EpssSourceError("Bezugsdatum weder in der Datei noch im Dateinamen enthalten")

    snapshot = epss_store.Snapshot(
        score_date=score_date,
        model_version=parsed.model_version,
        score_timestamp=parsed.score_timestamp,
        source_url=source_url,
        sha256=hashlib.sha256(payload).hexdigest(),
        row_count=len(parsed.rows),
        fetched_at=common.now_utc(),
        pinned=day is not None,
    )

    with closing(store.connect(db_path)) as conn:
        existing = epss_store.get_snapshot_for_date(conn, score_date)
        stored = existing is None or existing.sha256 != snapshot.sha256
        if stored:
            epss_store.save_snapshot(conn, snapshot, parsed.rows)
        elif snapshot.pinned:
            epss_store.pin(conn, score_date)
        pruned = epss_store.prune(conn, settings.epss_keep_snapshots if keep is None else keep)

    log.info("EPSS %s (%s): %d CVEs, %s", score_date, parsed.model_version, len(parsed.rows),
             "gespeichert" if stored else "unverändert")
    return SyncResult(snapshot=snapshot, stored=stored, pruned=pruned)


def _probability(value: str, lineno: int) -> float:
    """Parse a probability value from the file.

    Parameters
    ----------
    value : str
        Raw text of the field.
    lineno : int
        Line number in the file, used in error messages.

    Returns
    -------
    float
        The value, within [0, 1].

    Raises
    ------
    EpssSourceError
        If `value` is not a number or lies outside [0, 1].
    """
    try:
        number = float(value)
    except ValueError:
        raise EpssSourceError(f"Zeile {lineno}: kein Zahlenwert {value!r}") from None
    if not 0.0 <= number <= 1.0:   # also excludes NaN
        raise EpssSourceError(f"Zeile {lineno}: Wert {value!r} außerhalb von [0, 1]")
    return number
