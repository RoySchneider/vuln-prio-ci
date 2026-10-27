"""[3][4] Input signals of the exploitation and impact dimensions."""

from __future__ import annotations

from datetime import date
from typing import Optional

from pydantic import BaseModel, Field

from .enums_common import CvssSeverity
from .enums_v1 import CvssBand
from .enums_v2 import ProtectionLevel


class ExploitationSignals(BaseModel):
    """[3][5] Input signals of the exploitation dimension.

    Attributes
    ----------
    epss_score, epss_percentile : float or None
        EPSS score and percentile.
    epss_model_version : str or None
        EPSS model version of the snapshot, set even if the CVE is missing from it.
    epss_as_of : date or None
        Score date of the EPSS snapshot.
    kev_listed : bool
        Whether the CVE is listed in KEV.
    kev_date_added : str or None
        Date the CVE was added to KEV.
    kev_sources : list[str]
        KEV catalogues listing the CVE.
    exploit_db_listed : bool
        Whether Exploit-DB has an entry.
    exploit_db_ids : list[str]
        Exploit-DB entry IDs.
    exploit_db_commit : str or None
        Commit of the Exploit-DB snapshot, set even if the CVE is missing from it.
    metasploit_listed : bool
        Whether a Metasploit module of a counting type exists.
    metasploit_modules : list[str]
        Metasploit modules of counting types only.
    metasploit_commit : str or None
        Commit of the Metasploit snapshot.
    poc_available : bool
        Whether a proof of concept is available.
    composite_probability : float or None
        Former composite value; no longer used for method 1.
    """

    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    epss_model_version: Optional[str] = None   # snapshot, even if the CVE is missing from it
    epss_as_of: Optional[date] = None
    kev_listed: bool = False
    kev_date_added: Optional[str] = None
    kev_sources: list[str] = Field(default_factory=list)
    exploit_db_listed: bool = False
    exploit_db_ids: list[str] = Field(default_factory=list)
    exploit_db_commit: Optional[str] = None      # snapshot, even if the CVE is missing from it
    metasploit_listed: bool = False
    metasploit_modules: list[str] = Field(default_factory=list)   # counting module types only
    metasploit_commit: Optional[str] = None
    poc_available: bool = False
    composite_probability: Optional[float] = None


class ImpactSignals(BaseModel):
    """[4] Input signals of the impact dimension.

    Attributes
    ----------
    cvss_base_score : float or None
        CVSS base score.
    cvss_source : str or None
        Origin of the score, e.g. ``"NVD Primary 3.1"`` or ``"Bericht (Vektor 3.1)"``.
    cvss_vector : str or None
        CVSS vector string.
    cvss_version : str or None
        CVSS version.
    cvss_severity : CvssSeverity or None
        Coarse severity band.
    cvss_band : CvssBand or None
        CVSS range (method 1).
    cvss_metrics : dict
        Parsed vector metrics.
    business_impact_level : int or None
        5-level damage extent (from the app).
    protection_level : ProtectionLevel or None
        Protection need (method 2), derived from `business_impact_level`.
    """

    cvss_base_score: Optional[float] = None
    cvss_source: Optional[str] = None                   # e.g. "NVD Primary 3.1", "Bericht (Vektor 3.1)"
    cvss_vector: Optional[str] = None
    cvss_version: Optional[str] = None
    cvss_severity: Optional[CvssSeverity] = None
    cvss_band: Optional[CvssBand] = None                # method 1
    cvss_metrics: dict = Field(default_factory=dict)    # parsed vector metrics
    business_impact_level: Optional[int] = None         # 5-level damage extent (from the app)
    protection_level: Optional[ProtectionLevel] = None  # method 2, derived from business_impact_level
