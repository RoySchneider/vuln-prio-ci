from vuln_prio_ci.models import EnrichmentStatus, RawFinding
from vuln_prio_ci.normalize.identifiers import normalize


def test_cve_is_primary():
    raw = RawFinding(title="X", identifiers=["CVE-2024-12345", "GHSA-aaaa-bbbb-cccc"])
    norm = normalize(raw)
    assert norm.cve_id == "CVE-2024-12345"
    assert norm.cve_present is True
    assert norm.enrichment_status is EnrichmentStatus.resolved


def test_euvd_without_cve_is_pending():
    raw = RawFinding(title="X", identifiers=["EUVD-2025-10933"])
    norm = normalize(raw)
    assert norm.cve_id is None
    assert norm.euvd_id == "EUVD-2025-10933"
    assert norm.enrichment_status is EnrichmentStatus.pending


def test_sast_finding_is_cve_less_with_fingerprint():
    raw = RawFinding(title="Hardcoded secret", cwe="CWE-798", location="app/util.py:42")
    norm = normalize(raw)
    assert norm.cve_present is False
    assert norm.enrichment_status is EnrichmentStatus.cve_less
    assert norm.finding_fingerprint and norm.finding_fingerprint.startswith("sast-")


def test_fingerprint_is_stable():
    raw = RawFinding(title="Hardcoded secret", cwe="CWE-798", location="app/util.py:42")
    assert normalize(raw).finding_fingerprint == normalize(raw).finding_fingerprint
