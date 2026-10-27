"""CSV-Export des Vulnerability Reports mit den Spalten laut GitLab-Dokumentation."""

from vuln_prio_ci.ingest.gitlab_semgrep import parse_csv, parse_csv_with_stats

HEADER = ("Group Name,Project Name,Tool,Scanner Name,Status,Vulnerability,Details,Additional Info,Severity,"
          "CVE,CWE,Other Identifiers,Detected At,Location,Activity,Comments,Full Path,CVSS Vectors,Dismissal Reason\n")
ROWS = (
    'Example Organisation,Core,container_scanning,Trivy,detected,CVE-2019-19242 in sqlite-libs-3.26.0-r3,"SQLite mishandles pExpr",'
    ',medium,CVE-2019-19242,,"",2022-10-07 13:34:41 UTC,'
    '"{""image""=>""python:3.4-alpine"", ""dependency""=>{""package""=>{""name""=>""sqlite-libs""}, '
    '""version""=>""3.26.0-r3""}, ""operating_system""=>""alpine 3.9.2""}",true,"",example-organisation/core,'
    '"GitLab: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",\n'
    'Example Organisation,Core,dependency_scanning,Gemnasium,dismissed,Vite bypasses server.fs.deny,"...",,medium,CVE-2025-30208,,'
    '"GHSA-x574-m823-4x7w",2026-03-25 10:00:00 UTC,'
    '"{""file""=>""package-lock.json"", ""dependency""=>{""package""=>{""name""=>""vite""}, ""version""=>""6.2.2""}}",'
    'true,"",example-organisation/core,,false_positive\n'
    'Example Organisation,Core,sast,Semgrep,confirmed,Deserialization of Untrusted Data,"...",,critical,,502,"bandit.B506",'
    '2026-03-25 10:00:00 UTC,"{""file""=>""app/app.py"", ""start_line""=>39}",true,"",example-organisation/core,,\n'
)


def test_gitlab_export_columns():
    findings, skipped = parse_csv_with_stats(HEADER + ROWS)
    assert dict(skipped) == {"dismissed": 1}                 # verworfene Schwachstelle nicht übernommen
    assert len(findings) == 2
    cs, sast = findings
    assert cs.title == "CVE-2019-19242 in sqlite-libs-3.26.0-r3"     # Spalte "Vulnerability"
    assert cs.raw["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    assert cs.raw["finding_id"] == "CVE-2019-19242:sqlite-libs"
    assert cs.raw["image"] == "python:3.4-alpine"
    assert cs.raw["report_type"] == "container_scanning"
    assert sast.cwe == "CWE-502"
    assert "bandit.B506" in sast.identifiers                  # Spalte "Other Identifiers"
    assert sast.raw["file"] == "app/app.py" and sast.raw["line"] == 39


def test_old_sample_format_still_parses():
    findings = parse_csv("title,severity,scanner,cwe,location,identifiers\n"
                         "SQL Injection,High,Semgrep,CWE-89,app/db.py:12,CVE-2024-12345\n")
    assert findings[0].title == "SQL Injection"
    assert findings[0].raw["file"] == "app/db.py"
    assert findings[0].location == "app/db.py:12"
