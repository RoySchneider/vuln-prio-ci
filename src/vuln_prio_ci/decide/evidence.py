"""[5] Evidence grade (method 1, with CVE): hierarchical derivation, no composite.

The order is mandatory: KEV > Metasploit > ExploitDB/PoC > EPSS. Replaces the composite
formation from decide/exploitation.py for method 1 (implementation plan AP-2).
"""

from __future__ import annotations

from ..models import EvidenceGrade, ExploitationSignals


def derive_evidence_grade(sig: ExploitationSignals, tau: float) -> EvidenceGrade:
    """Derive the evidence grade from the exploitation signals.

    The first matching rule applies: KEV listing gives e6, a Metasploit module
    e5, an Exploit-DB entry or PoC e4. Otherwise the EPSS score decides: e2 if
    unknown, e3 if at least `tau`, e1 if below.

    Parameters
    ----------
    sig : ExploitationSignals
        Exploitation signals of the finding.
    tau : float
        EPSS threshold above which exploitation is considered predicted.

    Returns
    -------
    EvidenceGrade
        Evidence grade from e1 (low) to e6 (observed exploitation).
    """
    if sig.kev_listed:
        return EvidenceGrade.e6
    if sig.metasploit_listed:
        return EvidenceGrade.e5
    if sig.exploit_db_listed or sig.poc_available:
        return EvidenceGrade.e4
    if sig.epss_score is None:
        return EvidenceGrade.e2
    return EvidenceGrade.e3 if sig.epss_score >= tau else EvidenceGrade.e1
