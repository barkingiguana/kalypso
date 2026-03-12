"""Kalypso sidecar — automatic cert issuance and renewal for Docker Compose.

Runs alongside your services, issues certs on startup, writes them to a
shared volume, and re-issues before expiry. Optionally signals a container
to reload (e.g. nginx -s reload).

Environment variables:
    KALYPSO_DOMAINS     Comma-separated domains (required)
    KALYPSO_SERVER      Kalypso server URL (default: http://kalypso:8200)
    KALYPSO_CERT_DIR    Where to write cert/key files (default: /certs)
    KALYPSO_HOURS       Cert lifetime in hours (default: 24)
    KALYPSO_RELOAD_CMD  Command to run after cert renewal (optional)
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
from pathlib import Path

import httpx

logger = logging.getLogger("kalypso.sidecar")

DEFAULT_SERVER = "http://kalypso:8200"
DEFAULT_CERT_DIR = "/certs"
DEFAULT_HOURS = 24


def _wait_for_server(server: str, timeout: int = 120) -> None:
    """Wait for the Kalypso server to be healthy."""
    deadline = time.monotonic() + timeout
    url = f"{server}/health"
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=5)
            if r.status_code == 200:
                logger.info("Kalypso server is ready")
                return
        except httpx.HTTPError:
            pass
        time.sleep(2)
    raise RuntimeError(f"Kalypso server at {server} not ready after {timeout}s")


def _issue_and_write(
    server: str,
    domains: list[str],
    cert_dir: Path,
    hours: int,
) -> float:
    """Issue a cert and write files. Returns seconds until 50% lifetime."""
    logger.info("Requesting cert for %s (valid %dh)", domains, hours)
    r = httpx.post(
        f"{server}/certificates",
        json={"domains": domains, "hours": hours},
        timeout=30,
    )
    r.raise_for_status()
    data = r.json()

    cert_dir.mkdir(parents=True, exist_ok=True)
    (cert_dir / "cert.pem").write_text(data["certificate"])
    (cert_dir / "key.pem").write_text(data["private_key"])
    (cert_dir / "ca.pem").write_text(data["ca_certificate"])

    # Write a combined fullchain for servers that want it
    (cert_dir / "fullchain.pem").write_text(
        data["certificate"] + data["ca_certificate"]
    )

    logger.info("Wrote cert.pem, key.pem, ca.pem, fullchain.pem to %s", cert_dir)

    # Renew at 50% lifetime
    return hours * 3600 * 0.5


def _run_reload_cmd(cmd: str) -> None:
    """Execute the reload command."""
    logger.info("Running reload command: %s", cmd)
    try:
        subprocess.run(
            cmd,
            shell=True,
            check=True,
            timeout=30,
            capture_output=True,
            text=True,
        )
        logger.info("Reload command succeeded")
    except subprocess.CalledProcessError as e:
        logger.warning("Reload command failed (exit %d): %s", e.returncode, e.stderr)
    except subprocess.TimeoutExpired:
        logger.warning("Reload command timed out")


def run() -> None:
    """Main sidecar loop. Reads config from environment variables."""
    domains_str = os.environ.get("KALYPSO_DOMAINS", "")
    if not domains_str:
        raise RuntimeError("KALYPSO_DOMAINS environment variable is required")

    domains = [d.strip() for d in domains_str.split(",") if d.strip()]
    server = os.environ.get("KALYPSO_SERVER", DEFAULT_SERVER)
    cert_dir = Path(os.environ.get("KALYPSO_CERT_DIR", DEFAULT_CERT_DIR))
    hours = int(os.environ.get("KALYPSO_HOURS", str(DEFAULT_HOURS)))
    reload_cmd = os.environ.get("KALYPSO_RELOAD_CMD", "")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [kalypso-sidecar] %(message)s",
        datefmt="%H:%M:%S",
    )

    logger.info("Sidecar starting: domains=%s server=%s cert_dir=%s", domains, server, cert_dir)

    _wait_for_server(server)

    while True:
        try:
            sleep_seconds = _issue_and_write(server, domains, cert_dir, hours)
            if reload_cmd:
                _run_reload_cmd(reload_cmd)
        except Exception:
            logger.exception("Failed to issue cert, retrying in 30s")
            sleep_seconds = 30

        logger.info("Next renewal in %.0f minutes", sleep_seconds / 60)
        time.sleep(sleep_seconds)
