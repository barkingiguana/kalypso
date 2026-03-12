"""Core Certificate Authority implementation.

Kalypso CA generates a root CA certificate that developers trust once,
then uses it to sign short-lived leaf certificates for local services.
"""

from __future__ import annotations

import datetime
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Self

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# Sensible defaults — short-lived certs reduce blast radius if leaked.
DEFAULT_CA_DAYS = 3650  # 10 years for root CA
DEFAULT_CERT_HOURS = 24  # 24 hours for leaf certs
MAX_CERT_HOURS = 168  # 7 days max for leaf certs


@dataclass(frozen=True)
class CertBundle:
    """A certificate + private key pair."""

    certificate: x509.Certificate
    private_key: ec.EllipticCurvePrivateKey

    @property
    def cert_pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)

    @property
    def key_pem(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def save(self, cert_path: Path, key_path: Path) -> None:
        cert_path.write_bytes(self.cert_pem)
        key_path.write_bytes(self.key_pem)


@dataclass
class CertificateAuthority:
    """A local development Certificate Authority.

    Usage::

        ca = CertificateAuthority.init("Acme Dev")
        bundle = ca.issue("myapp.local", "*.myapp.local")
        bundle.save(Path("cert.pem"), Path("key.pem"))
    """

    root: CertBundle
    organization: str
    _issued: list[x509.Certificate] = field(default_factory=list, repr=False)

    # -- Factory ----------------------------------------------------------

    @classmethod
    def init(
        cls,
        organization: str = "Kalypso Dev CA",
        days: int = DEFAULT_CA_DAYS,
    ) -> Self:
        """Create a brand-new root CA."""
        key = _generate_key()
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{organization} Root CA"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        return cls(root=CertBundle(certificate=cert, private_key=key), organization=organization)

    @classmethod
    def load(cls, cert_path: Path, key_path: Path, organization: str = "Kalypso Dev CA") -> Self:
        """Load an existing CA from PEM files."""
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise TypeError("CA key must be an EC private key")
        return cls(root=CertBundle(certificate=cert, private_key=key), organization=organization)

    # -- Certificate issuance ---------------------------------------------

    def issue(
        self,
        *domains: str,
        hours: int = DEFAULT_CERT_HOURS,
        ip_addresses: list[str] | None = None,
    ) -> CertBundle:
        """Issue a short-lived leaf certificate for the given domains.

        Args:
            *domains: One or more domain names (e.g. ``"myapp.local"``,
                ``"*.myapp.local"``). At least one is required.
            hours: Lifetime in hours. Clamped to MAX_CERT_HOURS.
            ip_addresses: Optional IP addresses to include in the SAN.

        Returns:
            A :class:`CertBundle` with the signed certificate and its key.
        """
        if not domains:
            raise ValueError("At least one domain is required")
        if hours < 1:
            raise ValueError("Certificate lifetime must be at least 1 hour")
        hours = min(hours, MAX_CERT_HOURS)

        key = _generate_key()
        common_name = domains[0]
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        san_entries: list[x509.GeneralName] = [x509.DNSName(d) for d in domains]
        for addr in ip_addresses or []:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(addr)))

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.root.certificate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(hours=hours))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName(san_entries),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.root.private_key.public_key()
                ),
                critical=False,
            )
            .sign(self.root.private_key, hashes.SHA256())
        )
        bundle = CertBundle(certificate=cert, private_key=key)
        self._issued.append(cert)
        return bundle

    @property
    def issued_count(self) -> int:
        return len(self._issued)


def _generate_key() -> ec.EllipticCurvePrivateKey:
    """Generate a new ECDSA P-256 key (fast, secure, small)."""
    return ec.generate_private_key(ec.SECP256R1())
