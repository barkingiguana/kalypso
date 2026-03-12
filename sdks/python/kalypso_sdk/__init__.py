"""Kalypso Python SDK — request SSL certificates from a Kalypso CA server."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import urllib.request
import urllib.error
import json


@dataclass
class Certificate:
    """A certificate bundle returned by the Kalypso server."""

    certificate_pem: str
    private_key_pem: str
    ca_certificate_pem: str
    domains: list[str]
    not_after: str

    def save(self, cert_path: str | Path, key_path: str | Path) -> None:
        """Write the certificate and key to disk."""
        Path(cert_path).write_text(self.certificate_pem)
        Path(key_path).write_text(self.private_key_pem)

    def save_ca(self, ca_path: str | Path) -> None:
        """Write the CA certificate to disk."""
        Path(ca_path).write_text(self.ca_certificate_pem)

    def save_fullchain(self, path: str | Path) -> None:
        """Write cert + CA chain to a single file."""
        Path(path).write_text(self.certificate_pem + self.ca_certificate_pem)


class KalypsoClient:
    """Client for the Kalypso CA API.

    Usage::

        client = KalypsoClient("http://kalypso:8200")
        cert = client.issue("myapp.local", "*.myapp.local")
        cert.save("cert.pem", "key.pem")
    """

    def __init__(self, base_url: str = "http://localhost:8200") -> None:
        self.base_url = base_url.rstrip("/")

    def health(self) -> dict:
        """Check server health."""
        return self._get("/health")

    def ca_certificate(self) -> str:
        """Get the CA root certificate PEM."""
        return self._get("/ca.pem")["certificate"]

    def issue(
        self,
        *domains: str,
        hours: int = 24,
        ip_addresses: list[str] | None = None,
    ) -> Certificate:
        """Issue a new certificate.

        Args:
            *domains: One or more domain names.
            hours: Certificate lifetime in hours (max 168).
            ip_addresses: Optional IP SANs.

        Returns:
            A :class:`Certificate` with PEM-encoded cert and key.
        """
        body = {
            "domains": list(domains),
            "hours": hours,
        }
        if ip_addresses:
            body["ip_addresses"] = ip_addresses

        data = self._post("/certificates", body)
        return Certificate(
            certificate_pem=data["certificate"],
            private_key_pem=data["private_key"],
            ca_certificate_pem=data["ca_certificate"],
            domains=data["domains"],
            not_after=data["not_after"],
        )

    def _get(self, path: str) -> dict:
        req = urllib.request.Request(f"{self.base_url}{path}")
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())

    def _post(self, path: str, body: dict) -> dict:
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
