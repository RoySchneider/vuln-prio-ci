"""Schreibt requirements.lock und requirements-dev.lock: feste Versionen mit SHA-256 für das Image
und die Pipeline (Linux x86_64, CPython 3.15, nur Wheels).

    python scripts/lock.py

Löst über `pip install --dry-run --report` auf; braucht pip >= 26.2.2 (eMudhra/emSign-Vorfall:
ältere pip-Versionen vertrauen den kompromittierten Zwischenzertifikaten). Umgebungsmarker wertet
pip für den ausführenden Interpreter aus; unter Windows kommt so etwa colorama (pytest) hinzu, das
unter Linux nur zusätzlich installiert wird. Fehlt dem Lock ein Paket, bricht die Installation mit
--require-hashes ab, statt es ungeprüft nachzuladen.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MIN_PIP = (26, 2, 2)
TARGET = ["--python-version", "3.15", "--implementation", "cp", "--abi", "cp315", "--only-binary=:all:",
          "--platform", "manylinux_2_28_x86_64", "--platform", "manylinux_2_17_x86_64",
          "--platform", "manylinux2014_x86_64"]


def _resolve(requirements: Path) -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        subprocess.run([sys.executable, "-m", "pip", "install", "--dry-run", "--ignore-installed", "--quiet",
                        "--report", str(report), *TARGET, "-r", str(requirements)], check=True)
        return json.loads(report.read_text(encoding="utf-8"))["install"]


def _write(source: str, target: str) -> None:
    lines = [f"# Erzeugt mit scripts/lock.py aus {source} (Linux x86_64, CPython 3.15). Nicht von Hand ändern.",
             f"# Installation: pip install --require-hashes -r {target}"]
    for item in sorted(_resolve(ROOT / source), key=lambda i: i["metadata"]["name"].lower()):
        name, ver = item["metadata"]["name"].lower(), item["metadata"]["version"]
        digest = item["download_info"]["archive_info"]["hashes"]["sha256"]
        lines.append(f"{name}=={ver} \\\n    --hash=sha256:{digest}")
    (ROOT / target).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{target}: {len(lines) - 2} Pakete")


def main() -> int:
    pip_version = tuple(int(p) for p in version("pip").split(".")[:3])
    if pip_version < MIN_PIP:
        print(f"pip {version('pip')} zu alt, mindestens 26.2.2 nötig (siehe README)", file=sys.stderr)
        return 1
    _write("requirements.txt", "requirements.lock")
    _write("requirements-dev.txt", "requirements-dev.lock")
    return 0


if __name__ == "__main__":
    sys.exit(main())
