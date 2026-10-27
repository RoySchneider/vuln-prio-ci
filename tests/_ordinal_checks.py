"""Wiederverwendbare Prüffunktion: Regeltabelle ist ordinal monoton (AP-8, Prüfbedingung).

Für jede Schlüsseldimension gilt: steigt ihr Wert in der angegebenen Ordnung (mehr Nachweis,
höhere Schwere, größere Erreichbarkeit, größere Auswirkung, höherer Schutzbedarf), während alle
anderen Dimensionen unverändert bleiben, darf priority_rank nie sinken.
"""

from __future__ import annotations

from itertools import product


def assert_monotonic_ranks(
    table: dict[tuple[str, ...], tuple[str, int]],
    key_columns: tuple[str, ...],
    orders: dict[str, list[str]],
) -> None:
    for column in key_columns:
        order = orders[column]
        other_columns = [c for c in key_columns if c != column]
        other_value_lists = [orders[c] for c in other_columns]
        for other_values in product(*other_value_lists):
            fixed = dict(zip(other_columns, other_values))
            previous_rank = None
            for value in order:
                fixed[column] = value
                key = tuple(fixed[c] for c in key_columns)
                entry = table.get(key)
                if entry is None:
                    continue
                _, rank = entry
                if previous_rank is not None and rank < previous_rank:
                    raise AssertionError(
                        f"priority_rank sinkt bei steigendem {column}: "
                        f"Schlüssel {key} -> Rang {rank} < vorheriger Rang {previous_rank}"
                    )
                previous_rank = rank
