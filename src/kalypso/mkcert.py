"""mkcert integration for trust store management.

Kalypso uses mkcert (when available) for the one thing it does brilliantly:
installing root CA certificates into system and browser trust stores across
macOS, Linux, and Windows.

Kalypso handles everything else: short-lived certs, REST API, Docker sidecar,
auto-renewal, and SDKs.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class MkcertStatus:
    available: bool
    path: str | None = None
    version: str | None = None


def find_mkcert() -> MkcertStatus:
    """Check if mkcert is installed and available."""
    path = shutil.which("mkcert")
    if path is None:
        return MkcertStatus(available=False)

    try:
        result = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        version = result.stdout.strip() or result.stderr.strip()
        return MkcertStatus(available=True, path=path, version=version)
    except (subprocess.SubprocessError, OSError):
        return MkcertStatus(available=False)


def install_ca_to_trust_store(ca_cert_path: Path) -> bool:
    """Use mkcert to install a CA certificate into the system trust store.

    This is the primary reason we integrate with mkcert — it handles the
    cross-platform complexity of trust store installation:
    - macOS: System Keychain + NSS (Firefox)
    - Linux: NSS (Firefox/Chrome) + system trust store
    - Windows: Windows Certificate Store

    Returns True if successful, False otherwise.
    """
    status = find_mkcert()
    if not status.available:
        return False

    try:
        # Set CAROOT to our CA directory so mkcert uses our root CA
        env_caroot = str(ca_cert_path.parent)
        # mkcert expects rootCA.pem and rootCA-key.pem
        mkcert_cert = ca_cert_path.parent / "rootCA.pem"
        mkcert_key = ca_cert_path.parent / "rootCA-key.pem"

        # Symlink our CA files to mkcert's expected names
        ca_key_path = ca_cert_path.parent / "ca-key.pem"

        if not mkcert_cert.exists() and ca_cert_path.exists():
            mkcert_cert.symlink_to(ca_cert_path.name)
        if not mkcert_key.exists() and ca_key_path.exists():
            mkcert_key.symlink_to(ca_key_path.name)

        import os

        env = {**os.environ, "CAROOT": env_caroot}
        result = subprocess.run(
            [status.path, "-install"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def uninstall_ca_from_trust_store(ca_cert_path: Path) -> bool:
    """Remove the CA certificate from the system trust store."""
    status = find_mkcert()
    if not status.available:
        return False

    try:
        import os

        env = {**os.environ, "CAROOT": str(ca_cert_path.parent)}
        result = subprocess.run(
            [status.path, "-uninstall"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False
