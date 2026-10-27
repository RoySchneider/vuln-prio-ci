# Testberichte im Format der GitLab-Sicherheitsberichte

- `gl-sast-report.json`: unverändert aus dem GitLab-Quellcode übernommen
  (`spec/fixtures/security_reports/master/gl-sast-report-semgrep-for-multiple-findings.json`,
  Spiegel github.com/gitlabhq/gitlabhq, MIT-Lizenz). Semgrep-Befunde ohne CVE.
- `gl-dependency-scanning-report.json`, `gl-container-scanning-report.json`: für die Tests
  zusammengestellt nach dem Aufbau der Sicherheitsberichte (Schema 15.x: `vulnerabilities[]` mit
  `identifiers`, `location.dependency`, `cvss_vectors`). CVE-Kennungen sind echt, Pakete und Images
  Beispiele. Vor dem Betrieb gegen einen echten Bericht der eingesetzten Analysatoren prüfen.
