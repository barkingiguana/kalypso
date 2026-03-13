"""Tests for importing external CAs (mkcert, corporate, etc.)."""

from __future__ import annotations

import datetime
import tempfile
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from kalypso.ca import (
    CertificateAuthority,
    _validate_ca_cert,
    _validate_key_matches_cert,
    _signing_hash,
)


def _make_rsa_ca(bits: int = 3072) -> tuple[bytes, bytes]:
    """Generate an RSA CA cert+key (like mkcert does)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Corp"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Corp Root CA"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _make_leaf_cert() -> tuple[bytes, bytes]:
    """Generate a non-CA leaf cert (should fail import)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(hours=24))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


class TestImportExternalRSA:
    def test_import_rsa_ca(self):
        cert_pem, key_pem = _make_rsa_ca()
        ca = CertificateAuthority.import_external(cert_pem, key_pem)
        assert ca.root.certificate is not None
        assert isinstance(ca.root.private_key, rsa.RSAPrivateKey)

    def test_import_rsa_ca_can_issue(self):
        cert_pem, key_pem = _make_rsa_ca()
        ca = CertificateAuthority.import_external(cert_pem, key_pem)
        bundle = ca.issue("myapp.local", "*.myapp.local")
        assert bundle.certificate is not None
        assert "BEGIN CERTIFICATE" in bundle.cert_pem.decode()
        assert "BEGIN PRIVATE KEY" in bundle.key_pem.decode()

    def test_issued_cert_signed_by_rsa_ca(self):
        cert_pem, key_pem = _make_rsa_ca()
        ca = CertificateAuthority.import_external(cert_pem, key_pem)
        bundle = ca.issue("test.local")
        assert bundle.certificate.issuer == ca.root.certificate.subject

    def test_issued_cert_has_correct_san(self):
        cert_pem, key_pem = _make_rsa_ca()
        ca = CertificateAuthority.import_external(cert_pem, key_pem)
        bundle = ca.issue("a.local", "b.local")
        san = bundle.certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        names = san.value.get_values_for_type(x509.DNSName)
        assert "a.local" in names
        assert "b.local" in names

    def test_rsa_ca_load_roundtrip(self):
        cert_pem, key_pem = _make_rsa_ca()
        with tempfile.TemporaryDirectory() as td:
            cert_path = Path(td) / "ca.pem"
            key_path = Path(td) / "ca-key.pem"
            cert_path.write_bytes(cert_pem)
            key_path.write_bytes(key_pem)

            ca = CertificateAuthority.load(cert_path, key_path)
            bundle = ca.issue("test.local")
            assert bundle.certificate is not None


class TestImportValidation:
    def test_rejects_leaf_cert(self):
        cert_pem, key_pem = _make_leaf_cert()
        with pytest.raises(ValueError, match="CA:FALSE"):
            CertificateAuthority.import_external(cert_pem, key_pem)

    def test_rejects_key_mismatch(self):
        cert_pem, _ = _make_rsa_ca()
        _, wrong_key = _make_rsa_ca()  # Different key pair
        with pytest.raises(ValueError, match="does not match"):
            CertificateAuthority.import_external(cert_pem, wrong_key)

    def test_rejects_cert_without_basic_constraints(self):
        # Build a cert with no BasicConstraints at all
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "no-bc")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with pytest.raises(ValueError, match="no BasicConstraints"):
            CertificateAuthority.import_external(cert_pem, key_pem)

    def test_accepts_ec_p256_ca(self):
        """EC P-256 CAs (used by some tools) should work."""
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EC256 CA")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        ca = CertificateAuthority.import_external(cert_pem, key_pem)
        bundle = ca.issue("test.local")
        assert bundle.certificate is not None


class TestSigningHash:
    def test_ec_p384_uses_sha384(self):
        key = ec.generate_private_key(ec.SECP384R1())
        assert isinstance(_signing_hash(key), hashes.SHA384)

    def test_ec_p256_uses_sha256(self):
        key = ec.generate_private_key(ec.SECP256R1())
        assert isinstance(_signing_hash(key), hashes.SHA256)

    def test_rsa_uses_sha256(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        assert isinstance(_signing_hash(key), hashes.SHA256)
