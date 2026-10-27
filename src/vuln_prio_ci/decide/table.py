"""Rule tables as a class: loading by column name, explicit cache, no silent default.

Replaces `_load_table`/`@lru_cache` from the former decide/ssvc.py (implementation plan AP-4).
A miss is a programming error (missing or contradictory rule) and is not mapped to a default
priority but raises `RuleMissError`.
"""

from __future__ import annotations

import csv
from pathlib import Path

_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


class DecisionTableError(Exception):
    """Base class for errors when loading or querying a rule table."""


class RuleMissError(DecisionTableError):
    """Raised when no rule row exists for the given key (no silent default)."""


class DecisionTable:
    """A rule table: key from named columns -> (priority, priority_rank).

    The rows are read on first access and then kept (explicit cache, no `@lru_cache`),
    so that `reload()` allows a calibration without restarting the service.

    Parameters
    ----------
    filename : str
        Name of the CSV file in the ``rules`` directory.
    key_columns : tuple[str, ...]
        Names of the columns forming the lookup key. The file must also have
        the columns ``priority`` and ``priority_rank``.
    """

    def __init__(self, filename: str, key_columns: tuple[str, ...]) -> None:
        self._path = _RULES_DIR / filename
        self._key_columns = key_columns
        self._rows: dict[tuple[str, ...], tuple[str, int]] | None = None

    def lookup(self, key: tuple[str, ...]) -> tuple[str, int]:
        """Return (priority, priority_rank) for the key.

        Parameters
        ----------
        key : tuple[str, ...]
            Values of the key columns, in column order.

        Returns
        -------
        tuple[str, int]
            Priority level code and rank.

        Raises
        ------
        RuleMissError
            If the table has no row for the key.
        DecisionTableError
            If the file lacks required columns.
        """
        rows = self._rows_cached()
        try:
            return rows[key]
        except KeyError as exc:
            columns = ", ".join(self._key_columns)
            values = ", ".join(key)
            raise RuleMissError(
                f"{self._path.name}: kein Regeltreffer für ({columns}) = ({values})"
            ) from exc

    def reload(self) -> None:
        """Discard the cache; the next `lookup()` reads the file again."""
        self._rows = None

    def rows(self) -> dict[tuple[str, ...], tuple[str, int]]:
        """Return a read-only view of all loaded rule rows (e.g. for completeness/monotonicity tests).

        Returns
        -------
        dict[tuple[str, ...], tuple[str, int]]
            Copy of the table: key -> (priority, priority_rank).
        """
        return dict(self._rows_cached())

    def _rows_cached(self) -> dict[tuple[str, ...], tuple[str, int]]:
        """Return the rows, reading the file on first access."""
        if self._rows is None:
            self._rows = self._read()
        return self._rows

    def _read(self) -> dict[tuple[str, ...], tuple[str, int]]:
        """Read the rule rows from the CSV file.

        Returns
        -------
        dict[tuple[str, ...], tuple[str, int]]
            Key -> (priority, priority_rank).

        Raises
        ------
        DecisionTableError
            If required columns are missing.
        """
        rows: dict[tuple[str, ...], tuple[str, int]] = {}
        with self._path.open(encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            fieldnames = reader.fieldnames or []
            missing = [c for c in (*self._key_columns, "priority", "priority_rank") if c not in fieldnames]
            if missing:
                raise DecisionTableError(f"{self._path.name}: Spalten fehlen: {missing}")
            for row in reader:
                key = tuple(row[column].strip() for column in self._key_columns)
                rows[key] = (row["priority"].strip(), int(row["priority_rank"].strip()))
        return rows


# Method 1 (with CVE): evidence grade x CVSS range -> level + rank (1-18).
CVE_TABLE = DecisionTable("decision_table_cve.csv", ("evidence_grade", "cvss_band"))

# Method 2 (without CVE): exploitation state x exposure x impact x protection need -> level + rank (1-54).
CVELESS_TABLE = DecisionTable(
    "decision_table_cveless.csv",
    ("exploitation", "exposure", "technical_impact", "protection_level"),
)
