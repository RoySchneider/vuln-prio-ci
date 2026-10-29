"""CI-Befehl (python -m vuln_prio_ci run): Ende-zu-Ende gegen einen echten, kleinen Referenzdatenspeicher.

Der Speicher wird im Test mit den Modulen des Dienstes befüllt (EPSS, Exploit-DB, Metasploit, NVD,
KEV-Dump, Manifest); es gibt keinen Netzzugriff (EUVD-Einzelabruf ist im CI-Modus aus).
"""

from __future__ import annotations

import json
import shutil
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from vuln_prio_ci import store
from vuln_prio_ci import __main__ as ci_cli
from vuln_prio_ci.ci import run
from vuln_prio_ci.config import get_settings
from vuln_prio_ci.sources import manifest
from vuln_prio_ci.store import epss as epss_store
from vuln_prio_ci.store import exploits as exploit_store
from vuln_prio_ci.store import nvd as nvd_store

FIXTURES = Path(__file__).parent / "fixtures" / "gitlab"
TODAY = date(2026, 10, 14)

ASSESSMENTS = """
protection_level: normal
protection_level_basis: "Test"
findings:
  - id: "bandit.B506:app/app.py"
    exploitation_state: none
    exploitation_basis: "Suche ohne Treffer"
    exposure_level: lokal
    exposure_basis: "nur lokal"
    technical_impact: partial
    technical_impact_basis: "begrenzt"
    assessed_by: "Test"
    assessed_on: 2026-10-14
vex:
  - cve: CVE-2025-30208
    package: vite
    status: not_affected
    justification: "Entwicklungsserver wird nicht ausgeliefert"
"""


def _build_cache(cache: Path, created: datetime) -> None:
    conn = store.connect(cache / "reference.sqlite")
    fetched = created.isoformat(timespec="seconds")
    epss_store.save_snapshot(conn, epss_store.Snapshot(
        score_date=date(2026, 10, 13), model_version="v2026.06.15", score_timestamp=None,
        source_url="test", sha256="0", row_count=3, fetched_at=fetched),
        [("CVE-2021-44228", 0.94, 0.99), ("CVE-2022-3517", 0.01, 0.5), ("CVE-2025-30208", 0.6, 0.9)])
    for source, ref in ((exploit_store.EXPLOITDB, exploit_store.Reference("CVE-2025-30208", "52111", "webapps")),
                        (exploit_store.METASPLOIT, exploit_store.Reference("CVE-2021-44228", "exploit/multi/http/log4shell_header_injection", "exploit"))):
        exploit_store.save_snapshot(conn, exploit_store.Snapshot(
            source=source, commit_sha="abc123" + source, committed_at=fetched, source_url="test", sha256="0",
            ref_count=1, skipped_count=0, fetched_at=fetched), [ref])
    nvd_store.upsert(conn, [nvd_store.CvssRecord("CVE-2021-44228", 10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                                 "3.1", "Primary", "nvd@nist.gov", None, fetched)])
    nvd_store.set_sync(conn, fetched, fetched, True)
    conn.close()
    (cache / "kev-dump.json").write_text(json.dumps([
        {"cveId": "CVE-2021-44228", "dateAdded": "2021-12-10", "sources": ["CISA"]}]))
    manifest.write(cache, created_at=created)


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    cache = tmp_path / "reference-bundle"
    cache.mkdir()
    _build_cache(cache, datetime(2026, 10, 14, 3, 0, tzinfo=timezone.utc))
    monkeypatch.setenv("CACHE_DIR", str(cache))
    get_settings.cache_clear()
    reports = tmp_path / "project"
    reports.mkdir()
    for name in ("gl-sast-report.json", "gl-dependency-scanning-report.json", "gl-container-scanning-report.json"):
        shutil.copy(FIXTURES / name, reports / name)
    (reports / "assessments.yaml").write_text(ASSESSMENTS)
    yield reports
    get_settings.cache_clear()


def _opts(project: Path, **kwargs) -> run.RunOptions:
    defaults = dict(report_dir=project, assessments=project / "assessments.yaml",
                    output=project / "prioritization.json", codequality=project / "gl-code-quality-report.json",
                    today=TODAY)
    defaults.update(kwargs)
    return run.RunOptions(**defaults)


def test_full_run_with_immediate_finding(workspace):
    opts = _opts(workspace)
    outcome = run.execute(opts)
    run.write_outputs(outcome, opts)
    by_id = {r.finding_id: r for r in outcome.results}

    assert outcome.exit_code == run.EXIT_IMMEDIATE
    log4j = by_id["CVE-2021-44228:org.apache.logging.log4j/log4j-core"]
    assert log4j.priority.value == "immediate" and log4j.evidence_grade.value == "e6"
    assert log4j.cvss_source == "NVD Primary 3.1"                     # NVD vor Berichtsvektor
    minimatch = by_id["CVE-2022-3517:minimatch"]
    assert minimatch.cvss_source == "Bericht (Vektor 3.1)" and minimatch.cvss_base_score == 7.5
    assert minimatch.priority.value == "deferred"                      # E1/C2
    assert by_id["CVE-2023-0464:openssl"].priority.value == "planned"  # E2/C2
    assert by_id["bandit.B506:app/app.py"].priority.value == "deferred"  # Verfahren 2 mit Einschätzung
    assert [s.finding.raw["finding_id"] for s in outcome.vex_skipped] == ["CVE-2025-30208:vite"]
    assert [s.finding.raw["finding_id"] for s in outcome.undecided] == ["gosec.G106-1:og.go"]

    payload = json.loads(opts.output.read_text(encoding="utf-8"))
    assert payload["exit_code"] == 5
    assert payload["summary"]["Sofort"] == 1 and payload["summary"]["ohne Einschätzung"] == 1
    assert payload["reference_data"]["age_days"] == 0

    quality = json.loads(opts.codequality.read_text(encoding="utf-8"))
    assert len(quality) == len(outcome.results) + 1
    for entry in quality:
        assert set(entry) == {"description", "check_name", "fingerprint", "severity", "location"}
        assert entry["location"]["lines"]["begin"] >= 1
    severities = {e["location"]["path"]: e["severity"] for e in quality}
    assert severities["pom.xml"] == "blocker"
    assert severities["Dockerfile"] == "major"                          # Container-Befund
    assert severities["og.go"] == "info"                                # Einschätzung fehlt
    assert len({e["fingerprint"] for e in quality}) == len(quality)

    log = run.render_log(outcome, opts.assessments)
    assert "[Sofort] CVE-2021-44228" in log
    assert 'id: "gosec.G106-1:og.go"' in log                           # Vorlage für den fehlenden Eintrag
    assert "Exit-Code 5" in log


def test_exit_code_0_when_nothing_urgent_and_all_assessed(workspace):
    (workspace / "gl-dependency-scanning-report.json").unlink()
    (workspace / "assessments.yaml").write_text(ASSESSMENTS.replace("findings:\n", """findings:
  - id: "gosec.G106-1:og.go"
    vex_status: not_affected
    vex_justification: "Testcode"
"""))
    outcome = run.execute(_opts(workspace))
    assert outcome.exit_code == run.EXIT_OK
    assert outcome.orphaned == ["CVE-2025-30208:vite"]                 # vite-Befund nicht mehr im Lauf


def test_exit_code_3_for_missing_assessment(workspace):
    outcome = run.execute(_opts(workspace, report_dir=None, reports=[workspace / "gl-sast-report.json"]))
    assert outcome.exit_code == run.EXIT_LIMITED
    assert outcome.freshness is None                                    # ohne CVE-Befund keine Paketprüfung


def test_exit_code_3_for_stale_bundle(workspace):
    outcome = run.execute(_opts(workspace, reports=[workspace / "gl-container-scanning-report.json"],
                                report_dir=None, today=date(2026, 10, 20)))
    assert outcome.freshness.stale and outcome.freshness.age_days == 6
    assert outcome.exit_code == run.EXIT_LIMITED                         # openssl: Planmäßig, Paket veraltet


def test_exit_code_4_for_urgent(workspace):
    report = json.loads((workspace / "gl-dependency-scanning-report.json").read_text())
    report["vulnerabilities"] = [v for v in report["vulnerabilities"] if "log4j" not in v["name"]]
    (workspace / "gl-dependency-scanning-report.json").write_text(json.dumps(report))
    outcome = run.execute(_opts(workspace, assessments=None))            # vite ohne VEX-Aussage
    by_id = {r.finding_id: r for r in outcome.results}
    assert by_id["CVE-2025-30208:vite"].priority.value == "urgent"      # E4 (Exploit-DB) / C2
    assert outcome.exit_code == run.EXIT_URGENT


def test_missing_bundle_is_error(workspace, monkeypatch, tmp_path):
    monkeypatch.setenv("CACHE_DIR", str(tmp_path / "leer"))
    get_settings.cache_clear()
    with pytest.raises(run.RunError, match="kein Signalpaket"):
        run.execute(_opts(workspace))


def test_invalid_assessments_and_missing_report_are_errors(workspace):
    (workspace / "assessments.yaml").write_text("findings:\n  - id: x\n    exploitation_state: viel\n")
    with pytest.raises(run.RunError, match="Einschätzungsdatei ungültig"):
        run.execute(_opts(workspace))
    with pytest.raises(run.RunError, match="nicht gefunden"):
        run.execute(_opts(workspace, report_dir=None, reports=[workspace / "fehlt.json"]))


def test_cli_returns_exit_codes(workspace, capsys):
    code = ci_cli.main(["run", "--report-dir", str(workspace), "--assessments", str(workspace / "assessments.yaml"),
                        "--output", str(workspace / "p.json"), "--today", "2026-10-14"])
    assert code == 5
    assert "Exit-Code 5" in capsys.readouterr().out
    code = ci_cli.main(["run", "--report", str(workspace / "fehlt.json")])
    assert code == 1
    assert "FEHLER" in capsys.readouterr().err


def test_inventory_mode_cve_only(workspace):
    csv_path = workspace / "inventory.csv"
    csv_path.write_text(
        "Tool,Scanner Name,Status,Vulnerability,Severity,CVE,CWE,Other Identifiers,Location,CVSS Vectors\n"
        "dependency_scanning,Gemnasium,detected,log4j-core,critical,CVE-2021-44228,,,"
        '"{""file""=>""pom.xml"", ""dependency""=>{""package""=>{""name""=>""log4j-core""}, ""version""=>""2.14.1""}}",\n'
        "sast,Semgrep,detected,Deserialization,critical,,502,bandit.B506,"
        '"{""file""=>""app/app.py"", ""start_line""=>39}",\n'
        "dependency_scanning,Gemnasium,resolved,minimatch,high,CVE-2022-3517,,,,\n")
    outcome = run.execute(_opts(workspace, report_dir=None, gitlab_csv=csv_path, cve_only=True))
    assert [r.cve_id for r in outcome.results] == ["CVE-2021-44228"]     # SAST und behobene ausgelassen
    assert outcome.status_skipped == {"resolved": 1}
    assert outcome.exit_code == run.EXIT_IMMEDIATE
    # Einschätzung des ausgelassenen SAST-Befunds gilt nicht als verwaist, die VEX-Aussage ohne Befund schon
    assert outcome.orphaned == ["CVE-2025-30208:vite"]


def test_single_cves_only_in_terminal(workspace, capsys, monkeypatch):
    monkeypatch.chdir(workspace)
    before = sorted(p.name for p in workspace.parent.rglob("*"))
    code = ci_cli.main(["run", "--cve", "cve-2021-44228", "--cve", "CVE-2021-44228", "--cve", "CVE-2022-3517",
                        "--today", "2026-10-14"])
    out = capsys.readouterr().out
    assert code == run.EXIT_IMMEDIATE
    assert out.count("CVE-2021-44228: Sofort") == 1                    # Groß-/Kleinschreibung, doppelt
    assert "CVSS 10.0 (NVD Primary 3.1)" in out
    assert "CVE-2022-3517: " in out                                    # auch niedrige Stufen
    assert "Exit-Code 5" in out
    assert sorted(p.name for p in workspace.parent.rglob("*")) == before   # keine Dateien


def test_single_cve_invalid_or_conflicting(workspace, capsys):
    assert ci_cli.main(["run", "--cve", "CVE-21-1"]) == 1
    assert "ungültige CVE-Kennung: CVE-21-1" in capsys.readouterr().err
    for extra in (["--output", "p.json"], ["--gitlab-csv", "inventory.csv"], ["--report-dir", "."]):
        with pytest.raises(SystemExit) as exc:
            ci_cli.main(["run", "--cve", "CVE-2021-44228", *extra])
        assert exc.value.code == 2


def test_single_cve_without_bundle(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CACHE_DIR", str(tmp_path / "leer"))
    get_settings.cache_clear()
    try:
        assert ci_cli.main(["run", "--cve", "CVE-2021-44228"]) == 1
        assert "FEHLER" in capsys.readouterr().err
    finally:
        get_settings.cache_clear()


def test_single_cves_by_cvss_method(workspace, capsys, monkeypatch):
    monkeypatch.chdir(workspace)
    before = sorted(p.name for p in workspace.parent.rglob("*"))
    code = ci_cli.main(["run", "--cve", "CVE-2021-44228", "--cve", "CVE-2022-3517", "--cvss-method",
                        "--today", "2026-10-14"])
    out = capsys.readouterr().out
    assert code == run.EXIT_IMMEDIATE
    assert "CVE-2021-44228: Sofort, Rang 5" in out
    assert "CVSS-Verfahren[Schwere=critical]; CVSS 10.0 (NVD Primary 3.1)." in out
    assert "Verfahren 1" not in out
    assert "CVE-2022-3517: nicht priorisiert (CVSS-Verfahren benötigt einen CVSS-Basiswert)" in out
    assert sorted(p.name for p in workspace.parent.rglob("*")) == before   # keine Dateien


def test_cvss_method_only_with_single_cves(workspace):
    for argv in (["run", "--cvss-method"], ["run", "--report-dir", str(workspace), "--cvss-method"]):
        with pytest.raises(SystemExit) as exc:
            ci_cli.main(argv)
        assert exc.value.code == 2
    with pytest.raises(run.RunError, match="nur zusammen mit --cve"):
        run.execute(_opts(workspace, cvss_method=True))
