"""Tests for the core Certificate Authority."""

from __future__ import annotations

import datetime
import tempfile
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from kalypso.ca import (
    DEFAULT_CERT_HOURS,
    MAX_CERT_HOURS,
    CertBundle,
    CertificateAuthority,
)


class TestCertificateAuthorityInit:
    def test_creates_root_ca(self):
        ca = CertificateAuthority.init()
        assert ca.root.certificate is not None
        assert ca.root.private_key is not None

    def test_root_is_self_signed(self):
        ca = CertificateAuthority.init()
        cert = ca.root.certificate
        assert cert.issuer == cert.subject

    def test_root_has_ca_basic_constraint(self):
        ca = CertificateAuthority.init()
        bc = ca.root.certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True
        assert bc.critical is True
        assert bc.value.path_length == 0

    def test_root_has_key_usage(self):
        ca = CertificateAuthority.init()
        ku = ca.root.certificate.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.key_cert_sign is True
        assert ku.value.crl_sign is True
        assert ku.value.digital_signature is True
        assert ku.critical is True

    def test_root_uses_ecdsa_p384(self):
        ca = CertificateAuthority.init()
        pub = ca.root.private_key.public_key()
        assert isinstance(pub.curve, ec.SECP384R1)

    def test_custom_organization(self):
        ca = CertificateAuthority.init(organization="Acme Corp")
        cn = ca.root.certificate.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        assert cn[0].value == "Acme Corp Root CA"

    def test_custom_validity_days(self):
        ca = CertificateAuthority.init(days=365)
        cert = ca.root.certificate
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert abs(delta.days - 365) <= 1

    def test_issued_count_starts_at_zero(self):
        ca = CertificateAuthority.init()
        assert ca.issued_count == 0

    def test_root_has_subject_key_identifier(self):
        ca = CertificateAuthority.init()
        ski = ca.root.certificate.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        )
        assert ski is not None


class TestCertificateAuthorityIssue:
    @pytest.fixture()
    def ca(self) -> CertificateAuthority:
        return CertificateAuthority.init(organization="Test CA")

    def test_issue_single_domain(self, ca: CertificateAuthority):
        bundle = ca.issue("myapp.local")
        assert bundle.certificate is not None
        assert bundle.private_key is not None

    def test_issued_cert_signed_by_ca(self, ca: CertificateAuthority):
        bundle = ca.issue("myapp.local")
        issuer = bundle.certificate.issuer
        assert issuer == ca.root.certificate.subject

    def test_issued_cert_has_correct_san(self, ca: CertificateAuthority):
        bundle = ca.issue("myapp.local", "*.myapp.local")
        san = bundle.certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        names = san.value.get_values_for_type(x509.DNSName)
        assert "myapp.local" in names
        assert "*.myapp.local" in names

    def test_issued_cert_is_not_ca(self, ca: CertificateAuthority):
        bundle = ca.issue("myapp.local")
        bc = bundle.certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False
        assert bc.critical is True

    def test_issued_cert_has_server_auth_eku(self, ca: CertificateAuthority):
        bundle = ca.issue("myapp.local")
        eku = bundle.certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        from cryptography.x509.oid import ExtendedKeyUsageOID
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku.value

    def test_default_lifetime_is_24_hours(self, ca: CertificateAuthority):
        bundle = ca.issue("myapp.local")
        cert = bundle.certificate
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        expected = datetime.timedelta(hours=DEFAULT_CERT_HOURS)
        assert abs(delta - expected) < datetime.timedelta(minutes=1)

    def test_custom_lifetime(self, ca: CertificateAuthority):
        bundle = ca.issue("myapp.local", hours=4)
        cert = bundle.certificate
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert abs(delta - datetime.timedelta(hours=4)) < datetime.timedelta(minutes=1)

    def test_lifetime_clamped_to_max(self, ca: CertificateAuthority):
        bundle = ca.issue("myapp.local", hours=9999)
        cert = bundle.certificate
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert abs(delta - datetime.timedelta(hours=MAX_CERT_HOURS)) < datetime.timedelta(minutes=1)

    def test_issue_with_ip_addresses(self, ca: CertificateAuthority):
        bundle = ca.issue("myapp.local", ip_addresses=["127.0.0.1", "::1"])
        san = bundle.certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        ips = san.value.get_values_for_type(x509.IPAddress)
        import ipaddress
        assert ipaddress.IPv4Address("127.0.0.1") in ips
        assert ipaddress.IPv6Address("::1") in ips

    def test_no_domains_raises(self, ca: CertificateAuthority):
        with pytest.raises(ValueError, match="At least one domain"):
            ca.issue()

    def test_zero_hours_raises(self, ca: CertificateAuthority):
        with pytest.raises(ValueError, match="at least 1 hour"):
            ca.issue("myapp.local", hours=0)

    def test_issued_count_increments(self, ca: CertificateAuthority):
        ca.issue("a.local")
        ca.issue("b.local")
        assert ca.issued_count == 2

    def test_each_cert_has_unique_serial(self, ca: CertificateAuthority):
        b1 = ca.issue("a.local")
        b2 = ca.issue("b.local")
        assert b1.certificate.serial_number != b2.certificate.serial_number

    def test_each_cert_has_unique_key(self, ca: CertificateAuthority):
        b1 = ca.issue("a.local")
        b2 = ca.issue("b.local")
        k1 = b1.private_key.private_numbers().private_value
        k2 = b2.private_key.private_numbers().private_value
        assert k1 != k2

    def test_issued_cert_has_authority_key_identifier(self, ca: CertificateAuthority):
        bundle = ca.issue("myapp.local")
        aki = bundle.certificate.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        )
        assert aki is not None

    def test_cert_verifies_against_ca(self, ca: CertificateAuthority):
        """Verify the leaf cert chains to the CA root."""
        bundle = ca.issue("myapp.local")
        # Use the CA public key to verify the leaf cert signature
        ca.root.private_key.public_key().verify(
            bundle.certificate.signature,
            bundle.certificate.tbs_certificate_bytes,
            ec.ECDSA(bundle.certificate.signature_hash_algorithm),
        )


class TestCertBundle:
    def test_cert_pem_format(self):
        ca = CertificateAuthority.init()
        assert ca.root.cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")

    def test_key_pem_format(self):
        ca = CertificateAuthority.init()
        assert ca.root.key_pem.startswith(b"-----BEGIN PRIVATE KEY-----")

    def test_save_and_reload(self):
        ca = CertificateAuthority.init(organization="Roundtrip Test")
        with tempfile.TemporaryDirectory() as td:
            cert_path = Path(td) / "cert.pem"
            key_path = Path(td) / "key.pem"
            ca.root.save(cert_path, key_path)

            loaded = CertificateAuthority.load(cert_path, key_path, organization="Roundtrip Test")
            assert loaded.root.certificate.subject == ca.root.certificate.subject

    def test_fingerprint_is_sha256_hex(self):
        ca = CertificateAuthority.init()
        fp = ca.root.cert_fingerprint
        # SHA-256 = 64 hex chars + 31 colons = 95 chars
        assert len(fp) == 95
        assert ":" in fp

    def test_fingerprints_differ_per_ca(self):
        ca1 = CertificateAuthority.init()
        ca2 = CertificateAuthority.init()
        assert ca1.root.cert_fingerprint != ca2.root.cert_fingerprint

    def test_save_creates_key_with_0600_permissions(self):
        import stat
        ca = CertificateAuthority.init()
        with tempfile.TemporaryDirectory() as td:
            cert_path = Path(td) / "cert.pem"
            key_path = Path(td) / "key.pem"
            ca.root.save(cert_path, key_path)

            mode = key_path.stat().st_mode
            # Owner should have read/write, group+other should have nothing
            assert (mode & stat.S_IRWXG) == 0
            assert (mode & stat.S_IRWXO) == 0


class TestKeyPermissions:
    def test_verify_key_permissions_secure(self):
        from kalypso.ca import verify_key_permissions
        ca = CertificateAuthority.init()
        with tempfile.TemporaryDirectory() as td:
            key_path = Path(td) / "key.pem"
            ca.root.save(Path(td) / "cert.pem", key_path)
            assert verify_key_permissions(key_path) is True

    def test_verify_key_permissions_insecure(self):
        import os
        from kalypso.ca import verify_key_permissions
        ca = CertificateAuthority.init()
        with tempfile.TemporaryDirectory() as td:
            key_path = Path(td) / "key.pem"
            ca.root.save(Path(td) / "cert.pem", key_path)
            os.chmod(str(key_path), 0o644)
            assert verify_key_permissions(key_path) is False

    def test_verify_key_permissions_missing_file(self):
        from kalypso.ca import verify_key_permissions
        assert verify_key_permissions(Path("/nonexistent")) is False


class TestCertificateAuthorityLoad:
    def test_load_roundtrip(self):
        ca = CertificateAuthority.init(organization="Load Test")
        with tempfile.TemporaryDirectory() as td:
            cert_path = Path(td) / "ca.pem"
            key_path = Path(td) / "ca-key.pem"
            ca.root.save(cert_path, key_path)

            loaded = CertificateAuthority.load(cert_path, key_path, organization="Load Test")
            bundle = loaded.issue("test.local")
            assert bundle.certificate is not None

    def test_loaded_ca_can_issue(self):
        ca = CertificateAuthority.init()
        with tempfile.TemporaryDirectory() as td:
            cert_path = Path(td) / "ca.pem"
            key_path = Path(td) / "ca-key.pem"
            ca.root.save(cert_path, key_path)

            loaded = CertificateAuthority.load(cert_path, key_path)
            bundle = loaded.issue("myapp.local", "*.myapp.local")

            san = bundle.certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            names = san.value.get_values_for_type(x509.DNSName)
            assert "myapp.local" in names
