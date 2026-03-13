"""FastAPI server for Kalypso CA.

Exposes a simple REST API so containers and local services can request
certificates without needing the CLI or SDK installed locally.
"""

from __future__ import annotations

import datetime
import logging
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from kalypso.ca import DEFAULT_CERT_HOURS, MAX_CERT_HOURS, CertificateAuthority, fingerprint

logger = logging.getLogger("kalypso")

app = FastAPI(
    title="Kalypso",
    description="Local dev SSL certificate authority — like Let's Encrypt for localhost",
    version="0.1.0",
)

_ca: CertificateAuthority | None = None

CA_CERT_PATH = Path("/data/ca-cert.pem")
CA_KEY_PATH = Path("/data/ca-key.pem")


# -- Models ---------------------------------------------------------------


class IssueRequest(BaseModel):
    domains: list[str] = Field(min_length=1, description="Domain names for the certificate")
    hours: int = Field(
        default=DEFAULT_CERT_HOURS,
        ge=1,
        le=MAX_CERT_HOURS,
        description="Certificate lifetime in hours (max 168)",
    )
    ip_addresses: list[str] = Field(
        default_factory=list,
        description="Optional IP addresses for the SAN",
    )


class IssueResponse(BaseModel):
    certificate: str
    private_key: str
    domains: list[str]
    not_after: datetime.datetime
    ca_certificate: str


class HealthResponse(BaseModel):
    status: str
    ca_initialized: bool
    issued_count: int


# -- Startup / state ------------------------------------------------------


def get_ca() -> CertificateAuthority:
    global _ca  # noqa: PLW0603
    if _ca is not None:
        return _ca

    # Support importing external CAs via env vars (e.g. from mkcert or corporate CA)
    env_cert = os.environ.get("KALYPSO_CA_CERT")
    env_key = os.environ.get("KALYPSO_CA_KEY")

    if env_cert and env_key:
        env_cert_path = Path(env_cert)
        env_key_path = Path(env_key)
        if env_cert_path.exists() and env_key_path.exists():
            logger.info("Loading external CA from KALYPSO_CA_CERT=%s", env_cert)
            _ca = CertificateAuthority.load(env_cert_path, env_key_path)
            return _ca
        logger.warning("KALYPSO_CA_CERT/KEY set but files not found, falling back")

    if CA_CERT_PATH.exists() and CA_KEY_PATH.exists():
        logger.info("Loading existing CA from %s", CA_CERT_PATH)
        _ca = CertificateAuthority.load(CA_CERT_PATH, CA_KEY_PATH)
    else:
        logger.info("Initializing new CA")
        _ca = CertificateAuthority.init()
        CA_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
        _ca.root.save(CA_CERT_PATH, CA_KEY_PATH)

    return _ca


def set_ca(ca: CertificateAuthority) -> None:
    """Inject a CA instance (used in tests)."""
    global _ca  # noqa: PLW0603
    _ca = ca


# -- Endpoints ------------------------------------------------------------


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    ca = get_ca()
    return HealthResponse(
        status="ok",
        ca_initialized=True,
        issued_count=ca.issued_count,
    )


@app.get("/ca.pem", response_class=PlainTextResponse)
def ca_certificate_pem() -> PlainTextResponse:
    """Download the CA root certificate as raw PEM (trust this once).

    Usage: curl http://localhost:8200/ca.pem > kalypso-ca.pem
    """
    ca = get_ca()
    return PlainTextResponse(
        content=ca.root.cert_pem.decode(),
        media_type="application/x-pem-file",
    )


@app.get("/ca.json")
def ca_certificate_json() -> dict:
    """CA certificate with metadata as JSON."""
    ca = get_ca()
    cert = ca.root.certificate
    return {
        "certificate": ca.root.cert_pem.decode(),
        "fingerprint": fingerprint(cert),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "subject": cert.subject.rfc4514_string(),
    }


@app.post("/certificates", response_model=IssueResponse)
def issue_certificate(req: IssueRequest) -> IssueResponse:
    """Issue a new short-lived certificate."""
    ca = get_ca()
    try:
        bundle = ca.issue(
            *req.domains,
            hours=req.hours,
            ip_addresses=req.ip_addresses if req.ip_addresses else None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return IssueResponse(
        certificate=bundle.cert_pem.decode(),
        private_key=bundle.key_pem.decode(),
        domains=req.domains,
        not_after=bundle.certificate.not_valid_after_utc,
        ca_certificate=ca.root.cert_pem.decode(),
    )
