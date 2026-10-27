"""Check of the CA bundle before network access (eMudhra/emSign incident, October 2026).

httpx verifies server certificates against the bundle from certifi. The intermediate certificates
of eMudhra under the emSign root had insecure private keys; anyone who keeps trusting the root is
open to man-in-the-middle attacks. It is only removed from certifi 2026.10.19 on. An image or
environment with an older certifi therefore aborts instead of silently continuing to trust it.
Notes from the Python community:
https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576
"""

from __future__ import annotations

MIN_CERTIFI = (2026, 10, 19)


class CaBundleOutdated(Exception):
    """Raised when certifi is older than MIN_CERTIFI or its version is unreadable."""


def _parse(version: str) -> tuple[int, ...]:
    """Parse a version string into a tuple of its first three numeric parts.

    Parameters
    ----------
    version : str
        Version such as ``"2026.10.19"``.

    Returns
    -------
    tuple[int, ...]
        Up to three integer components.

    Raises
    ------
    CaBundleOutdated
        If a component is not an integer.
    """
    try:
        return tuple(int(part) for part in version.split(".")[:3])
    except ValueError as exc:
        raise CaBundleOutdated(f"certifi-Version nicht lesbar: {version!r}") from exc


def check_ca_bundle(version: str | None = None) -> None:
    """Check that the installed certifi no longer trusts the emSign root.

    Parameters
    ----------
    version : str, optional
        certifi version to check. Defaults to the installed version.

    Raises
    ------
    CaBundleOutdated
        If the version is older than `MIN_CERTIFI` or cannot be parsed.
    """
    if version is None:
        import certifi
        version = certifi.__version__
    if _parse(version) < MIN_CERTIFI:
        required = ".".join(f"{p:02d}" for p in MIN_CERTIFI)
        raise CaBundleOutdated(
            f"certifi {version} vertraut noch der emSign-Wurzel (eMudhra-Vorfall); "
            f"mindestens {required} nötig: pip install --upgrade \"certifi>={required}\"")
