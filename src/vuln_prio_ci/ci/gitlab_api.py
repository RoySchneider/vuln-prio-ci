"""Access to the GitLab API from the pipeline job.

- Publish and download the signal bundle (Generic Package Registry of the project vuln-prio).
  Authentication with the job token (CI_JOB_TOKEN); for access from a product project, vuln-prio
  must list that project in its job token allowlist (Settings > CI/CD > Job token permissions).
- Export the vulnerability inventory of the main branch (Vulnerability Export API, Ultimate only).
  The job token is not sufficient for this; a project or personal access token with the scope
  `read_api` is needed in the variable GITLAB_API_TOKEN.
"""

from __future__ import annotations

import io
import os
import sqlite3
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import quote

import httpx

from ..sources import manifest as manifest_mod

PACKAGE_NAME = "reference-bundle"
FILE_NAME = "reference-bundle.tar.gz"
BUNDLE_FILES = ("reference.sqlite", "kev-dump.json", "cve-euvd-mapping.csv", manifest_mod.MANIFEST_NAME)
_TIMEOUT = httpx.Timeout(300.0)


class ApiError(Exception):
    """Raised when accessing the GitLab API fails."""


def _api_url() -> str:
    """Return the base URL of the GitLab API from ``CI_API_V4_URL``.

    Raises
    ------
    ApiError
        If the variable is not set.
    """
    url = os.environ.get("CI_API_V4_URL")
    if not url:
        raise ApiError("CI_API_V4_URL nicht gesetzt (Befehl ist für den Pipeline-Job gedacht)")
    return url.rstrip("/")


def _project(project: str) -> str:
    """Return a project ID or path in the form required in API URLs (numeric ID or URL-encoded path)."""
    return project if project.isdigit() else quote(project, safe="")


def _headers(prefer_private: bool = False) -> dict:
    """Build the authentication header.

    Parameters
    ----------
    prefer_private : bool, optional
        Use the access token ``GITLAB_API_TOKEN`` and never the job token.
        Without it, the job token is used if present.

    Returns
    -------
    dict
        Header with ``PRIVATE-TOKEN`` or ``JOB-TOKEN``.

    Raises
    ------
    ApiError
        If no suitable token is available.
    """
    private = os.environ.get("GITLAB_API_TOKEN")
    job = os.environ.get("CI_JOB_TOKEN")
    if private and (prefer_private or not job):
        return {"PRIVATE-TOKEN": private}
    if job and not prefer_private:
        return {"JOB-TOKEN": job}
    raise ApiError("kein Token: GITLAB_API_TOKEN bzw. CI_JOB_TOKEN fehlt")


def _check(resp: httpx.Response, what: str) -> httpx.Response:
    """Raise an error for an HTTP error response.

    Parameters
    ----------
    resp : httpx.Response
        Response to check.
    what : str
        Description of the operation, used in the error message.

    Returns
    -------
    httpx.Response
        `resp`, unchanged, if it is not an error.

    Raises
    ------
    ApiError
        If the response has an error status.
    """
    if resp.is_error:
        raise ApiError(f"{what}: HTTP {resp.status_code} {resp.text[:200]}")
    return resp


# --- Signal bundle ---------------------------------------------------------------------------------

def build_bundle(cache_dir: Path | str) -> bytes:
    """Pack the cache directory as tar.gz (the WAL is first checkpointed into the database).

    Parameters
    ----------
    cache_dir : Path or str
        Cache directory. Only the files in `BUNDLE_FILES` that exist are packed.

    Returns
    -------
    bytes
        The compressed archive.
    """
    cache_dir = Path(cache_dir)
    db = cache_dir / "reference.sqlite"
    if db.exists():
        conn = sqlite3.connect(db)
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            conn.close()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name in BUNDLE_FILES:
            path = cache_dir / name
            if path.exists():
                tar.add(path, arcname=name)
    return buffer.getvalue()


def extract_bundle(content: bytes, dest: Path | str) -> list[str]:
    """Extract a signal bundle into a directory.

    Only the expected flat files are extracted; paths and links are skipped.

    Parameters
    ----------
    content : bytes
        The compressed archive.
    dest : Path or str
        Target directory; created if necessary.

    Returns
    -------
    list[str]
        Names of the extracted files.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    names = []
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
        for member in tar.getmembers():
            # only the expected flat files, no paths/links (protection against path traversal)
            if not member.isfile() or member.name not in BUNDLE_FILES:
                continue
            source = tar.extractfile(member)
            if source is None:
                continue
            target = dest / member.name
            target.write_bytes(source.read())
            os.utime(target, (member.mtime, member.mtime))
            names.append(member.name)
    return names


def publish_bundle(cache_dir: Path | str, project: str, version: Optional[str] = None) -> str:
    """Upload the signal bundle to the Generic Package Registry of a project.

    Parameters
    ----------
    cache_dir : Path or str
        Cache directory to pack.
    project : str
        Numeric ID or path of the project.
    version : str, optional
        Package version. Defaults to the current UTC time as ``YYYY.MM.DD-HHMMSS``.

    Returns
    -------
    str
        The published version.

    Raises
    ------
    ApiError
        If no token is available or the upload fails.
    """
    version = version or datetime.now(timezone.utc).strftime("%Y.%m.%d-%H%M%S")
    url = (f"{_api_url()}/projects/{_project(project)}/packages/generic/"
           f"{PACKAGE_NAME}/{version}/{FILE_NAME}")
    resp = httpx.put(url, content=build_bundle(cache_dir), headers=_headers(), timeout=_TIMEOUT)
    _check(resp, "Signalpaket hochladen")
    return version


def latest_bundle_version(project: str) -> str:
    """Return the version of the most recently created signal bundle.

    Parameters
    ----------
    project : str
        Numeric ID or path of the project.

    Returns
    -------
    str
        Version of the newest package.

    Raises
    ------
    ApiError
        If the request fails or the project has no bundle.
    """
    url = f"{_api_url()}/projects/{_project(project)}/packages"
    params = {"package_type": "generic", "package_name": PACKAGE_NAME,
              "order_by": "created_at", "sort": "desc", "per_page": 20}
    resp = _check(httpx.get(url, params=params, headers=_headers(), timeout=_TIMEOUT), "Pakete auflisten")
    packages = [p for p in resp.json() if p.get("name") == PACKAGE_NAME]
    if not packages:
        raise ApiError(f"kein Paket {PACKAGE_NAME} im Projekt {project}")
    return packages[0]["version"]


def fetch_bundle(project: str, dest: Path | str, version: Optional[str] = None) -> tuple[str, list[str]]:
    """Download a signal bundle and extract it.

    Parameters
    ----------
    project : str
        Numeric ID or path of the project holding the bundle.
    dest : Path or str
        Target directory.
    version : str, optional
        Package version. Defaults to the latest.

    Returns
    -------
    version : str
        The downloaded version.
    names : list[str]
        Names of the extracted files.

    Raises
    ------
    ApiError
        If no token is available, no bundle exists, or the download fails.
    """
    version = version or latest_bundle_version(project)
    url = (f"{_api_url()}/projects/{_project(project)}/packages/generic/"
           f"{PACKAGE_NAME}/{version}/{FILE_NAME}")
    resp = _check(httpx.get(url, headers=_headers(), timeout=_TIMEOUT, follow_redirects=True),
                  "Signalpaket laden")
    return version, extract_bundle(resp.content, dest)


# --- Vulnerability inventory (operating mode 2) ----------------------------------------------------

def export_inventory(project: str, output: Path | str, timeout_s: int = 600, poll_s: int = 10) -> Path:
    """Export the vulnerability inventory of a project as CSV.

    Creates an export via the Vulnerability Export API, waits until it is
    finished and downloads it. Requires an access token (``GITLAB_API_TOKEN``).

    Parameters
    ----------
    project : str
        Numeric ID or path of the project.
    output : Path or str
        File the CSV is written to.
    timeout_s : int, optional
        Maximum time to wait for the export in seconds (default 600).
    poll_s : int, optional
        Seconds between status requests (default 10).

    Returns
    -------
    Path
        Path of the written CSV file.

    Raises
    ------
    ApiError
        If no token is available, a request fails, the export fails, or it is
        not finished within `timeout_s`.
    """
    headers = _headers(prefer_private=True)
    base = _api_url()
    resp = _check(httpx.post(f"{base}/security/projects/{_project(project)}/vulnerability_exports",
                             data={"export_format": "csv"}, headers=headers, timeout=_TIMEOUT),
                  "Export anlegen")
    export_id = resp.json()["id"]
    deadline = time.monotonic() + timeout_s
    while True:
        status = _check(httpx.get(f"{base}/security/vulnerability_exports/{export_id}",
                                  headers=headers, timeout=_TIMEOUT), "Exportstatus abfragen")
        if status.status_code == 200 and status.json().get("status") == "finished":
            break
        if status.json().get("status") == "failed":
            raise ApiError(f"Export {export_id} fehlgeschlagen")
        if time.monotonic() > deadline:
            raise ApiError(f"Export {export_id} nach {timeout_s} s nicht fertig")
        time.sleep(poll_s)
    csv = _check(httpx.get(f"{base}/security/vulnerability_exports/{export_id}/download",
                           headers=headers, timeout=_TIMEOUT, follow_redirects=True), "Export laden")
    Path(output).write_bytes(csv.content)
    return Path(output)
