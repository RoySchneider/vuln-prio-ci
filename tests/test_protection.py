import pytest

from vuln_prio_ci.decide.protection import combined_business_impact_level, derive_protection_level
from vuln_prio_ci.models import ProtectionLevel, ProtectionNeed


@pytest.mark.parametrize(
    "level,expected",
    [
        (1, ProtectionLevel.normal),
        (2, ProtectionLevel.normal),
        (3, ProtectionLevel.high),
        (4, ProtectionLevel.high),
        (5, ProtectionLevel.very_high),
    ],
)
def test_mapping_table(level, expected):
    result, is_default = derive_protection_level(level)
    assert result == expected
    assert is_default is False


def test_missing_level_defaults_to_very_high():
    result, is_default = derive_protection_level(None)
    assert result == ProtectionLevel.very_high
    assert is_default is True


def test_out_of_range_level_raises():
    with pytest.raises(ValueError):
        derive_protection_level(6)


def test_combined_takes_maximum_over_protection_needs():
    levels = {
        ProtectionNeed.confidentiality: 2,
        ProtectionNeed.integrity: 5,
        ProtectionNeed.availability: 3,
    }
    assert combined_business_impact_level(levels) == 5


def test_combined_single_need():
    assert combined_business_impact_level({ProtectionNeed.availability: 3}) == 3


def test_combined_empty_is_none():
    assert combined_business_impact_level({}) is None
