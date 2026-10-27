"""Check of the signal bundle: present and not older than the maximum age.

What counts is the age of the bundle according to the manifest (`created_at`): the daily run writes
the manifest only after all sources were fetched successfully. If the manifest is missing (local
operation without a bundle), the oldest fetch date of the individual sources applies.

- No reference data store, or neither EPSS snapshot nor KEV dump: signal bundle missing
  (technical error).
- Bundle older than the maximum age or a single source missing: limited result (warning).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Optional

from ..sources import manifest as manifest_mod

REQUIRED_SOURCES = ("epss", "kev", "exploitdb", "metasploit", "nvd")


class BundleMissing(Exception):
    """Raised when there is no usable signal bundle in the cache directory."""


@dataclass
class Freshness:
    """Result of the freshness check of the signal bundle.

    Attributes
    ----------
    created_at : str or None
        Creation time according to the manifest, None without a manifest.
    age_days : int or None
        Age of the bundle in days, None if it cannot be determined.
    max_age_days : int
        Maximum permitted age in days.
    stale : bool
        Whether the bundle is older than the maximum age or its age is unknown.
    missing_sources : list[str]
        Required sources without data.
    sources : dict
        State of each source, see `sources.manifest.describe`.
    """

    created_at: Optional[str]          # creation time according to the manifest (None without a manifest)
    age_days: Optional[int]
    max_age_days: int
    stale: bool
    missing_sources: list[str] = field(default_factory=list)
    sources: dict = field(default_factory=dict)

    @property
    def limited(self) -> bool:
        """Whether the result is limited: the bundle is stale or a source is missing."""
        return self.stale or bool(self.missing_sources)

    def as_dict(self) -> dict:
        """Return the check result as a dictionary for the JSON output."""
        return {
            "created_at": self.created_at, "age_days": self.age_days, "max_age_days": self.max_age_days,
            "stale": self.stale, "missing_sources": self.missing_sources, "sources": self.sources,
        }


def _day(timestamp: Optional[str]) -> Optional[date]:
    """Convert a date or ISO-8601 timestamp to a UTC date.

    Parameters
    ----------
    timestamp : str or None
        ``YYYY-MM-DD`` or an ISO-8601 timestamp; one without a time zone is
        assumed to be UTC.

    Returns
    -------
    date or None
        The date in UTC, or None if `timestamp` is empty.
    """
    if not timestamp:
        return None
    text = timestamp.strip()
    if len(text) == 10:
        return date.fromisoformat(text)
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).date()


def check(cache_dir: Path | str, max_age_days: int, today: Optional[date] = None) -> Freshness:
    """Check that the signal bundle is present and not too old.

    Parameters
    ----------
    cache_dir : Path or str
        Cache directory containing the signal bundle.
    max_age_days : int
        Maximum permitted age of the bundle in days.
    today : date, optional
        Reference day. Defaults to the current day in UTC.

    Returns
    -------
    Freshness
        Age, staleness and missing sources of the bundle.

    Raises
    ------
    BundleMissing
        If the cache directory has neither reference store nor KEV dump, or
        the bundle contains neither EPSS scores nor a KEV dump.
    """
    cache_dir = Path(cache_dir)
    today = today or datetime.now(timezone.utc).date()
    if not (cache_dir / "reference.sqlite").exists() and not (cache_dir / manifest_mod.KEV_NAME).exists():
        raise BundleMissing(f"kein Signalpaket in {cache_dir} (reference.sqlite und kev-dump.json fehlen)")

    manifest = manifest_mod.read(cache_dir)
    sources = manifest["sources"] if manifest and "sources" in manifest else manifest_mod.describe(cache_dir)
    if not sources.get("epss") and not sources.get("kev"):
        raise BundleMissing(f"Signalpaket in {cache_dir} enthält weder EPSS-Werte noch KEV-Dump")
    missing = [name for name in REQUIRED_SOURCES if not sources.get(name)]

    if manifest and manifest.get("created_at"):
        created_at = manifest["created_at"]
        reference_day = _day(created_at)
    else:
        created_at = None
        days = []
        for name, info in sources.items():
            if not info:
                continue
            days.append(_day(info.get("score_date") if name == "epss" else info.get("fetched_at")))
        reference_day = min((d for d in days if d), default=None)
    age = (today - reference_day).days if reference_day else None
    stale = age is None or age > max_age_days
    return Freshness(created_at=created_at, age_days=age, max_age_days=max_age_days, stale=stale,
                     missing_sources=missing, sources=sources)
