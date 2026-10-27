"""Configuration via environment variables (in the pipeline job: CI/CD variables).

Locally also from .env (template: .env.example). Thresholds are disclosed, calibratable
parameters (methodology sect. 3.5), deliberately configurable instead of hard-coded.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings, read from environment variables and ``.env``.

    Field names map to upper-case environment variables (e.g. ``cache_dir`` to
    ``CACHE_DIR``). Unknown variables are ignored.

    Attributes
    ----------
    euvd_base_url : str
        Base URL of the EUVD API.
    epss_bulk_base_url : str
        Base URL of the EPSS bulk files.
    epss_keep_snapshots : int
        Number of EPSS daily snapshots to keep; 0 keeps all.
    exploitdb_commit_url, exploitdb_file_url, exploitdb_commits_until_url : str
        URL templates for Exploit-DB (GitLab); ``{ref}``, ``{branch}`` and
        ``{until}`` are filled in.
    metasploit_commit_url, metasploit_file_url, metasploit_commits_until_url : str
        URL templates for Metasploit (GitHub).
    metasploit_module_types : str
        Comma-separated module types that count as Metasploit evidence.
    exploit_keep_snapshots : int
        Number of snapshots to keep per exploit source; 0 keeps all.
    nvd_api_url : str
        URL of the NVD CVE API 2.0.
    nvd_api_key : str
        NVD API key; empty for the lower rate limit.
    euvd_live_lookup : bool
        Whether a single EUVD lookup is made per finding.
    cache_dir : str
        Cache directory, which also holds the reference data store.
    epss_threshold : float
        EPSS threshold tau for the evidence grades e3/e1.
    cvss_band_high, cvss_band_critical : float
        Lower limits of the CVSS ranges c2 and c3.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # External sources (only for fetching the signal bundle; the prioritisation run is offline)
    euvd_base_url: str = "https://euvdservices.enisa.europa.eu/api"
    epss_bulk_base_url: str = "https://epss.empiricalsecurity.com"
    # EPSS daily snapshots to keep (pinned reference dates do not count); 0 = keep all
    epss_keep_snapshots: int = 30

    # Exploit-DB (GitLab) and Metasploit (GitHub); {ref} = branch or commit SHA
    exploitdb_commit_url: str = "https://gitlab.com/api/v4/projects/exploit-database%2Fexploitdb/repository/commits/{ref}"
    exploitdb_file_url: str = "https://gitlab.com/exploit-database/exploitdb/-/raw/{ref}/files_exploits.csv"
    metasploit_commit_url: str = "https://api.github.com/repos/rapid7/metasploit-framework/commits/{ref}"
    # Commit list of a branch up to a point in time (for --as-of: last commit before a reference date)
    exploitdb_commits_until_url: str = (
        "https://gitlab.com/api/v4/projects/exploit-database%2Fexploitdb/repository/commits"
        "?ref_name={branch}&until={until}&per_page=1"
    )
    metasploit_commits_until_url: str = (
        "https://api.github.com/repos/rapid7/metasploit-framework/commits?sha={branch}&until={until}&per_page=1"
    )
    metasploit_file_url: str = "https://raw.githubusercontent.com/rapid7/metasploit-framework/{ref}/db/modules_metadata_base.json"
    # Module types that count as Metasploit evidence (comma-separated); all are stored
    metasploit_module_types: str = "exploit"
    # Snapshots to keep per source (pinned ones do not count); 0 = keep all
    exploit_keep_snapshots: int = 30

    # NVD (CVE API 2.0) for the CVSS base scores; without a key 5 requests per 30 s, with a key 50
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str = ""

    # Single EUVD lookup per finding in the decision path. Off in the CI pipeline (offline operation):
    # the job calls no external services, CVSS comes from the NVD data or the report vector.
    euvd_live_lookup: bool = True

    cache_dir: str = "./cache"   # also holds the reference data store reference.sqlite

    # EPSS threshold tau (method 1, evidence grade E3/E1; appendix C, subject of examination in AP-9)
    epss_threshold: float = 0.088
    # CVSS range limits (method 1, appendix C): c3 from cvss_band_critical, c2 from cvss_band_high
    cvss_band_high: float = 7.0
    cvss_band_critical: float = 9.0


@lru_cache
def get_settings() -> Settings:
    """Return the application settings, created once and cached.

    Call ``get_settings.cache_clear()`` to re-read the environment.

    Returns
    -------
    Settings
        The settings instance.
    """
    return Settings()
