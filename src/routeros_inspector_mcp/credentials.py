"""Credential resolver for an operator-configured Ansible Vault.

Resolves credential_ref tokens into username/password pairs by calling
``ansible-vault`` as a subprocess.

Design:
- No vault parsing library; the Ansible Vault CLI remains the source of truth.
- Never logs secrets. Cache is in-memory only for the server process lifetime.
- credential_ref is the base name; _username and _password suffixes are appended.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from functools import lru_cache
from pathlib import Path

VAULT_DIR = os.environ.get(
    "ROUTEROS_INSPECTOR_VAULT_DIR", str(Path.home() / ".config" / "routeros-inspector-mcp")
)
VAULT_FILE = os.environ.get("ROUTEROS_INSPECTOR_VAULT_FILE", "vault.yml")
VAULT_PASS_FILE = os.environ.get("ROUTEROS_INSPECTOR_VAULT_PASSWORD_FILE", ".vault_pass")


class CredentialError(Exception):
    """Raised when credential resolution fails."""


class Credentials:
    """Resolved username/password pair."""

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password

    def __repr__(self) -> str:
        return f"Credentials(username={self.username!r}, password=***)"


def _configured_path(value: str) -> str:
    path = Path(value).expanduser()
    if path.is_absolute():
        return str(path)
    return str(Path(VAULT_DIR) / path)


def _vault_path() -> str:
    return _configured_path(VAULT_FILE)


def _vault_pass_path() -> str:
    return _configured_path(VAULT_PASS_FILE)


def _vault_variable_name(credential_ref: str) -> tuple[str, str]:
    """Split credential_ref into (username_var, password_var).

    credential_ref 'vault_mikrotik_readonly' ->
        ('vault_mikrotik_readonly_username', 'vault_mikrotik_readonly_password')
    """
    return (credential_ref + "_username", credential_ref + "_password")


@lru_cache(maxsize=16)
def resolve_credentials(credential_ref: str) -> Credentials:
    """Resolve a credential_ref to a Credentials object.

    Reads the operator-configured vault via an ``ansible-vault`` CLI subprocess.
    Result is cached in-memory for the process lifetime.

    Raises CredentialError if resolution fails.
    """
    vault_file = _vault_path()
    vault_pass = _vault_pass_path()

    if not os.path.isfile(vault_file):
        raise CredentialError(
            f"Vault file not found: {vault_file}. "
            "Set ROUTEROS_INSPECTOR_VAULT_DIR or ROUTEROS_INSPECTOR_VAULT_FILE"
        )

    if not os.path.isfile(vault_pass):
        raise CredentialError(
            f"Vault password file not found: {vault_pass}"
        )

    try:
        result = subprocess.run(
            [
                "ansible-vault",
                "view",
                vault_file,
                "--vault-password-file", vault_pass,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except FileNotFoundError:
        raise CredentialError("ansible-vault not found. Install ansible-core.")
    except subprocess.TimeoutExpired:
        raise CredentialError("ansible-vault subprocess timed out")

    if result.returncode != 0:
        # Never log stderr which might contain vault errors with sensitive context
        raise CredentialError(
            f"ansible-vault failed (rc={result.returncode}) for {credential_ref!r}"
        )

    # Parse YAML key: value output
    vault_vars: dict[str, str] = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            vault_vars[key.strip()] = value.strip()

    username_var, password_var = _vault_variable_name(credential_ref)

    username = vault_vars.get(username_var)
    password = vault_vars.get(password_var)

    if not username or not password:
        raise CredentialError(
            f"Missing vault variables for {credential_ref!r}: "
            f"have keys {list(vault_vars.keys())}"
        )

    return Credentials(username=username, password=password)


def credential_ref_fingerprint(credential_ref: str) -> str:
    """Return a short non-secret fingerprint for logging/auditing.

    Used in audit logs instead of the credential_ref itself.
    """
    return hashlib.sha256(credential_ref.encode()).hexdigest()[:12]
