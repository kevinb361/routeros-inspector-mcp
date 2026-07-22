"""Safety tests for the private fixture refresh helper."""

from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).parent.parent
SCRIPT = ROOT / "scripts" / "refresh_routeros_fixture.py"


def run_helper(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def test_refresh_requires_explicit_source_mode():
    result = run_helper("edge-router")

    assert result.returncode == 2
    assert "one of the arguments --from-artifacts --capture-live is required" in result.stderr


def test_live_refresh_requires_all_external_paths():
    result = run_helper("edge-router", "--capture-live")

    assert result.returncode == 2
    assert "--capture-live requires" in result.stderr
    assert "--ansible-root" in result.stderr
    assert "--inventory-path" in result.stderr
    assert "--playbook-path" in result.stderr
    assert "--vault-password-file" in result.stderr
