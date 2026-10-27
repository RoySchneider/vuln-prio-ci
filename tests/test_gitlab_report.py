"""Import der GitLab-Sicherheitsberichte (SAST, Dependency Scanning, Container Scanning)."""

from pathlib import Path

import pytest

from vuln_prio_ci.ingest import gitlab_report

FIXTURES = Path(__file__).parent / "fixtures" / "gitlab"


def test_sast_report_from_gitlab_fixture():
    findings = gitlab_report.load_report(FIXTURES / "gl-sast-report.json")
    assert len(findings) == 2
    first = findings[0]
    assert first.title == "Deserialization of Untrusted Data"   # 'message', kein 'name'
    assert first.identifiers == ["CWE-502"]                      # CWE-Wert ist im Bericht nur "502"
    assert first.raw["rule_id"] == "bandit.B506"                 # primäre Kennung = erste
    assert first.raw["finding_id"] == "bandit.B506:app/app.py"   # Regel:Datei, ohne Zeile
    assert first.raw["line"] == 39
    assert first.raw["report_type"] == "sast"
    assert first.scanner == "Semgrep"


def test_dependency_scanning_report():
    findings = gitlab_report.load_report(FIXTURES / "gl-dependency-scanning-report.json")
    log4j = findings[0]
    assert log4j.identifiers[0] == "CVE-2021-44228"
    assert log4j.raw["finding_id"] == "CVE-2021-44228:org.apache.logging.log4j/log4j-core"
    assert log4j.raw["file"] == "pom.xml"
    assert log4j.raw["cvss_vector"].startswith("CVSS:3.1/")
    vite = findings[1]
    assert vite.raw["cvss_vector"].startswith("CVSS:3.1/")      # 3.x vor 4.0
    assert vite.raw["report_type"] == "dependency_scanning"


def test_container_scanning_report():
    [finding] = gitlab_report.load_report(FIXTURES / "gl-container-scanning-report.json")
    assert finding.raw["image"].endswith("product-core:1.4.0")
    assert finding.raw["file"] is None
    assert finding.raw["finding_id"] == "CVE-2023-0464:openssl"
    assert finding.scanner == "Trivy"


def test_find_reports_only_known_files(tmp_path):
    (tmp_path / "gl-sast-report.json").write_text("{}")
    (tmp_path / "gl-code-quality-report.json").write_text("[]")
    assert [p.name for p in gitlab_report.find_reports(tmp_path)] == ["gl-sast-report.json"]


@pytest.mark.parametrize("content", ["{kaputt", "[]", '{"version": "15.0.0"}'])
def test_invalid_report_raises(tmp_path, content):
    path = tmp_path / "gl-sast-report.json"
    path.write_text(content)
    with pytest.raises(gitlab_report.ReportError):
        gitlab_report.load_report(path)


def test_missing_report_raises(tmp_path):
    with pytest.raises(gitlab_report.ReportError):
        gitlab_report.load_report(tmp_path / "fehlt.json")
