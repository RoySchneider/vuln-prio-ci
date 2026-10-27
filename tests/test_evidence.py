from vuln_prio_ci.decide.evidence import derive_evidence_grade
from vuln_prio_ci.models import EvidenceGrade, ExploitationSignals

TAU = 0.088


def _sig(**kwargs) -> ExploitationSignals:
    return ExploitationSignals(**kwargs)


def test_kev_and_metasploit_yield_e6():
    sig = _sig(kev_listed=True, metasploit_listed=True)
    assert derive_evidence_grade(sig, TAU) == EvidenceGrade.e6


def test_metasploit_only_yields_e5():
    sig = _sig(metasploit_listed=True)
    assert derive_evidence_grade(sig, TAU) == EvidenceGrade.e5


def test_exploit_db_only_yields_e4():
    sig = _sig(exploit_db_listed=True)
    assert derive_evidence_grade(sig, TAU) == EvidenceGrade.e4


def test_poc_only_yields_e4():
    sig = _sig(poc_available=True)
    assert derive_evidence_grade(sig, TAU) == EvidenceGrade.e4


def test_no_signal_epss_above_tau_yields_e3():
    sig = _sig(epss_score=0.2)
    assert derive_evidence_grade(sig, TAU) == EvidenceGrade.e3


def test_no_signal_epss_missing_yields_e2():
    sig = _sig(epss_score=None)
    assert derive_evidence_grade(sig, TAU) == EvidenceGrade.e2


def test_no_signal_epss_below_tau_yields_e1():
    sig = _sig(epss_score=0.01)
    assert derive_evidence_grade(sig, TAU) == EvidenceGrade.e1


def test_precedence_kev_over_metasploit_and_epss():
    sig = _sig(kev_listed=True, exploit_db_listed=True, epss_score=0.9)
    assert derive_evidence_grade(sig, TAU) == EvidenceGrade.e6


def test_precedence_metasploit_over_exploit_db_and_epss():
    sig = _sig(metasploit_listed=True, exploit_db_listed=True, epss_score=0.9)
    assert derive_evidence_grade(sig, TAU) == EvidenceGrade.e5
