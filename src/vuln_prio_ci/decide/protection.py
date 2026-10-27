"""Derive the protection need (method 2) from the 5-level damage extent (appendix C, AP-6).

Source of the damage extent: `RawFinding.business_impact_levels`, per protection goal
(PROTECTION_NEED: confidentiality/integrity/availability); in the pipeline the assessment file
usually states the protection need directly. Two steps, both fixed decisions (appendix C):
  1. combined_business_impact_level: maximum over the given protection goals.
  2. derive_protection_level: map the combined level (1..5) to PROTECTION_LEVEL.
"""

from __future__ import annotations

from typing import Optional

from ..models import ProtectionLevel, ProtectionNeed

# Damage extent (1..5) -> protection need (appendix C, fixed decision).
_LEVEL_TO_PROTECTION = {
    1: ProtectionLevel.normal,
    2: ProtectionLevel.normal,
    3: ProtectionLevel.high,
    4: ProtectionLevel.high,
    5: ProtectionLevel.very_high,
}

DEFAULT_PROTECTION_LEVEL = ProtectionLevel.very_high   # undetermined -> very high (appendix C)


def combined_business_impact_level(levels: dict[ProtectionNeed, int]) -> Optional[int]:
    """Return the maximum over the given protection goals.

    Parameters
    ----------
    levels : dict[ProtectionNeed, int]
        Damage extent (1..5) per protection goal.

    Returns
    -------
    int or None
        The highest level, or None if no level is given (undetermined).
    """
    if not levels:
        return None
    return max(levels.values())


def derive_protection_level(business_impact_level: Optional[int]) -> tuple[ProtectionLevel, bool]:
    """Map the combined damage extent to the protection need.

    Parameters
    ----------
    business_impact_level : int or None
        Combined damage extent (1..5), or None if undetermined.

    Returns
    -------
    protection_level : ProtectionLevel
        The protection need; ``very_high`` if undetermined.
    default_applied : bool
        True if the default was used because the level is undetermined.

    Raises
    ------
    ValueError
        If the level is outside 1..5.
    """
    if business_impact_level is None:
        return DEFAULT_PROTECTION_LEVEL, True
    try:
        return _LEVEL_TO_PROTECTION[business_impact_level], False
    except KeyError as exc:
        raise ValueError(f"Schadensausmaß außerhalb 1..5: {business_impact_level}") from exc
