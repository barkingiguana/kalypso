"""Native trust store management — no external dependencies.

Installs and removes Kalypso's root CA certificate from system and browser
trust stores on macOS, Linux, and Windows. Zero dependencies beyond the
OS tools that ship with every platform.

Security notes:
- Trust store operations require elevated privileges (sudo/admin)
- Only the public CA certificate is written to the trust store
- The CA private key never leaves ~/.kalypso/
- All subprocess calls use explicit argument lists (no shell injection)
- Timeouts prevent hanging on interactive prompts
"""

from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("kalypso.trust")

# Timeout for trust store operations (seconds)
_CMD_TIMEOUT = 30


@dataclass
class TrustResult:
    """Result of a trust store operation."""

    success: bool
    stores_modified: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def detect_platform() -> str:
    """Detect the current platform: 'macos', 'linux', or 'windows'."""
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    if system == "windows":
        return "windows"
    return "linux"


def install(ca_cert_path: Path) -> TrustResult:
    """Install the CA certificate into all available trust stores.

    Detects the platform and calls the appropriate installer(s). On Linux,
    this covers both the system trust store AND browser NSS databases.

    Args:
        ca_cert_path: Path to the CA certificate PEM file.

    Returns:
        TrustResult with success status and details.
    """
    if not ca_cert_path.exists():
        return TrustResult(success=False, errors=[f"CA cert not found: {ca_cert_path}"])

    plat = detect_platform()
    if plat == "macos":
        return _install_macos(ca_cert_path)
    if plat == "windows":
        return _install_windows(ca_cert_path)
    return _install_linux(ca_cert_path)


def uninstall(ca_cert_path: Path) -> TrustResult:
    """Remove the CA certificate from all available trust stores.

    Args:
        ca_cert_path: Path to the CA certificate PEM file.

    Returns:
        TrustResult with success status and details.
    """
    if not ca_cert_path.exists():
        return TrustResult(success=False, errors=[f"CA cert not found: {ca_cert_path}"])

    plat = detect_platform()
    if plat == "macos":
        return _uninstall_macos(ca_cert_path)
    if plat == "windows":
        return _uninstall_windows(ca_cert_path)
    return _uninstall_linux(ca_cert_path)


def trust_instructions(ca_cert_path: Path) -> list[str]:
    """Return human-readable trust installation instructions for all platforms."""
    p = str(ca_cert_path)
    return [
        f"macOS:   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {p}",
        f"Ubuntu:  sudo cp {p} /usr/local/share/ca-certificates/kalypso.crt && sudo update-ca-certificates",
        f"Fedora:  sudo trust anchor {p}",
        f"Arch:    sudo trust anchor {p}",
        f"Windows: certutil -addstore Root {p}",
        f"Node.js: export NODE_EXTRA_CA_CERTS={p}",
    ]


# -- macOS ----------------------------------------------------------------


def _install_macos(ca_cert_path: Path) -> TrustResult:
    result = TrustResult(success=False)

    # System Keychain
    try:
        _run_cmd([
            "sudo", "security", "add-trusted-cert",
            "-d", "-r", "trustRoot",
            "-k", "/Library/Keychains/System.keychain",
            str(ca_cert_path),
        ])
        result.stores_modified.append("macOS System Keychain")
        result.success = True
    except TrustStoreError as e:
        result.errors.append(f"System Keychain: {e}")

    # Firefox NSS (if certutil available)
    _install_nss(ca_cert_path, result)

    return result


def _uninstall_macos(ca_cert_path: Path) -> TrustResult:
    result = TrustResult(success=False)

    try:
        _run_cmd([
            "sudo", "security", "remove-trusted-cert",
            "-d", str(ca_cert_path),
        ])
        result.stores_modified.append("macOS System Keychain")
        result.success = True
    except TrustStoreError as e:
        result.errors.append(f"System Keychain: {e}")

    _uninstall_nss(result)
    return result


# -- Linux ----------------------------------------------------------------


def _install_linux(ca_cert_path: Path) -> TrustResult:
    result = TrustResult(success=False)

    # Try update-ca-certificates (Debian/Ubuntu)
    ca_certs_dir = Path("/usr/local/share/ca-certificates")
    if ca_certs_dir.exists() and shutil.which("update-ca-certificates"):
        try:
            dest = ca_certs_dir / "kalypso-dev-ca.crt"
            _run_cmd(["sudo", "cp", str(ca_cert_path), str(dest)])
            _run_cmd(["sudo", "update-ca-certificates"])
            result.stores_modified.append("System trust store (update-ca-certificates)")
            result.success = True
        except TrustStoreError as e:
            result.errors.append(f"update-ca-certificates: {e}")

    # Try trust anchor (Fedora/RHEL/Arch)
    elif shutil.which("trust"):
        try:
            _run_cmd(["sudo", "trust", "anchor", str(ca_cert_path)])
            result.stores_modified.append("System trust store (p11-kit trust anchor)")
            result.success = True
        except TrustStoreError as e:
            result.errors.append(f"trust anchor: {e}")
    else:
        result.errors.append("No supported trust store tool found (need update-ca-certificates or trust)")

    # Firefox/Chrome NSS databases
    _install_nss(ca_cert_path, result)

    return result


def _uninstall_linux(ca_cert_path: Path) -> TrustResult:
    result = TrustResult(success=False)

    dest = Path("/usr/local/share/ca-certificates/kalypso-dev-ca.crt")
    if dest.exists() and shutil.which("update-ca-certificates"):
        try:
            _run_cmd(["sudo", "rm", str(dest)])
            _run_cmd(["sudo", "update-ca-certificates", "--fresh"])
            result.stores_modified.append("System trust store (update-ca-certificates)")
            result.success = True
        except TrustStoreError as e:
            result.errors.append(f"update-ca-certificates: {e}")

    elif shutil.which("trust"):
        try:
            _run_cmd(["sudo", "trust", "anchor", "--remove", str(ca_cert_path)])
            result.stores_modified.append("System trust store (p11-kit trust anchor)")
            result.success = True
        except TrustStoreError as e:
            result.errors.append(f"trust anchor: {e}")

    _uninstall_nss(result)
    return result


# -- Windows --------------------------------------------------------------


def _install_windows(ca_cert_path: Path) -> TrustResult:
    result = TrustResult(success=False)

    try:
        _run_cmd(["certutil", "-addstore", "Root", str(ca_cert_path)])
        result.stores_modified.append("Windows Certificate Store (Root)")
        result.success = True
    except TrustStoreError as e:
        result.errors.append(f"certutil: {e}")

    return result


def _uninstall_windows(ca_cert_path: Path) -> TrustResult:
    result = TrustResult(success=False)

    try:
        _run_cmd(["certutil", "-delstore", "Root", str(ca_cert_path)])
        result.stores_modified.append("Windows Certificate Store (Root)")
        result.success = True
    except TrustStoreError as e:
        result.errors.append(f"certutil: {e}")

    return result


# -- NSS (Firefox/Chrome on Linux/macOS) ----------------------------------


_NSS_DB_SEARCH_PATHS = [
    Path.home() / ".mozilla/firefox",
    Path.home() / ".pki/nssdb",
    Path.home() / "snap/firefox/common/.mozilla/firefox",
    Path.home() / "Library/Application Support/Firefox/Profiles",
]

_KALYPSO_NSS_NAME = "Kalypso Dev CA"


def _find_nss_dbs() -> list[Path]:
    """Find all NSS certificate databases on the system."""
    certutil_path = shutil.which("certutil")
    if certutil_path is None:
        return []

    dbs: list[Path] = []
    for search_path in _NSS_DB_SEARCH_PATHS:
        if not search_path.exists():
            continue
        # NSS dbs are directories containing cert9.db or cert8.db
        for db_file in search_path.rglob("cert9.db"):
            dbs.append(db_file.parent)
        for db_file in search_path.rglob("cert8.db"):
            parent = db_file.parent
            if parent not in dbs:
                dbs.append(parent)

    return dbs


def _install_nss(ca_cert_path: Path, result: TrustResult) -> None:
    """Install the CA cert into all found NSS databases (Firefox, Chrome)."""
    certutil_path = shutil.which("certutil")
    if certutil_path is None:
        return

    for db_dir in _find_nss_dbs():
        try:
            # -A: add cert, -t C,,: trusted CA for SSL, -n: nickname
            _run_cmd([
                certutil_path, "-A",
                "-d", f"sql:{db_dir}",
                "-t", "C,,",
                "-n", _KALYPSO_NSS_NAME,
                "-i", str(ca_cert_path),
            ])
            result.stores_modified.append(f"NSS db: {db_dir}")
        except TrustStoreError as e:
            result.errors.append(f"NSS {db_dir}: {e}")


def _uninstall_nss(result: TrustResult) -> None:
    """Remove the CA cert from all found NSS databases."""
    certutil_path = shutil.which("certutil")
    if certutil_path is None:
        return

    for db_dir in _find_nss_dbs():
        try:
            _run_cmd([
                certutil_path, "-D",
                "-d", f"sql:{db_dir}",
                "-n", _KALYPSO_NSS_NAME,
            ])
            result.stores_modified.append(f"NSS db: {db_dir}")
        except TrustStoreError as e:
            result.errors.append(f"NSS {db_dir}: {e}")


# -- Helpers --------------------------------------------------------------


class TrustStoreError(Exception):
    """A trust store operation failed."""


def _run_cmd(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    """Run a command with safety guards.

    - Explicit argument list (no shell=True, no injection)
    - Timeout to prevent hanging on interactive prompts
    - No environment variable leakage
    """
    logger.debug("Running: %s", " ".join(cmd))

    # Build a minimal, clean environment
    clean_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/usr/sbin:/bin:/sbin"),
        "HOME": os.environ.get("HOME", "/root"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_CMD_TIMEOUT,
            env=clean_env,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or f"exit code {result.returncode}"
            raise TrustStoreError(detail)
        return result
    except subprocess.TimeoutExpired as e:
        raise TrustStoreError(f"Command timed out after {_CMD_TIMEOUT}s") from e
    except FileNotFoundError as e:
        raise TrustStoreError(f"Command not found: {cmd[0]}") from e
