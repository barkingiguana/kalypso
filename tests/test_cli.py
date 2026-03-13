"""Tests for the Kalypso CLI."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from click.testing import CliRunner

from kalypso.cli import main


class TestInitCommand:
    def test_init_creates_ca_files(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            result = runner.invoke(main, ["--data-dir", td, "init"])
            assert result.exit_code == 0
            assert (Path(td) / "ca-cert.pem").exists()
            assert (Path(td) / "ca-key.pem").exists()

    def test_init_refuses_if_already_exists(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            runner.invoke(main, ["--data-dir", td, "init"])
            result = runner.invoke(main, ["--data-dir", td, "init"])
            assert result.exit_code == 1
            assert "already exists" in result.output

    def test_init_custom_org(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            result = runner.invoke(main, ["--data-dir", td, "init", "--org", "My Org"])
            assert result.exit_code == 0
            assert "Root CA created" in result.output

    def test_init_shows_fingerprint(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            result = runner.invoke(main, ["--data-dir", td, "init"])
            assert "Fingerprint:" in result.output

    def test_init_shows_trust_instructions(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            result = runner.invoke(main, ["--data-dir", td, "init"])
            assert "kalypso trust" in result.output
            assert "macOS" in result.output

    def test_init_creates_key_with_secure_permissions(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            runner.invoke(main, ["--data-dir", td, "init"])
            key_path = Path(td) / "ca-key.pem"
            mode = key_path.stat().st_mode
            # Group and other should have no access
            assert (mode & (stat.S_IRWXG | stat.S_IRWXO)) == 0


class TestIssueCommand:
    def test_issue_creates_cert_files(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            data_dir = Path(td) / "ca"
            out_dir = Path(td) / "certs"
            runner.invoke(main, ["--data-dir", str(data_dir), "init"])
            result = runner.invoke(main, [
                "--data-dir", str(data_dir),
                "issue", "myapp.local", "--out", str(out_dir),
            ])
            assert result.exit_code == 0
            assert (out_dir / "cert.pem").exists()
            assert (out_dir / "key.pem").exists()

    def test_issue_multiple_domains(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            data_dir = Path(td) / "ca"
            out_dir = Path(td) / "certs"
            runner.invoke(main, ["--data-dir", str(data_dir), "init"])
            result = runner.invoke(main, [
                "--data-dir", str(data_dir),
                "issue", "myapp.local", "*.myapp.local",
                "--out", str(out_dir),
            ])
            assert result.exit_code == 0
            assert "myapp.local" in result.output

    def test_issue_without_init_fails(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            result = runner.invoke(main, [
                "--data-dir", td, "issue", "myapp.local",
            ])
            assert result.exit_code == 1
            assert "No CA found" in result.output

    def test_issue_with_custom_hours(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            data_dir = Path(td) / "ca"
            out_dir = Path(td) / "certs"
            runner.invoke(main, ["--data-dir", str(data_dir), "init"])
            result = runner.invoke(main, [
                "--data-dir", str(data_dir),
                "issue", "myapp.local",
                "--hours", "4",
                "--out", str(out_dir),
            ])
            assert result.exit_code == 0
            assert "4 hours" in result.output

    def test_issue_with_ip(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            data_dir = Path(td) / "ca"
            out_dir = Path(td) / "certs"
            runner.invoke(main, ["--data-dir", str(data_dir), "init"])
            result = runner.invoke(main, [
                "--data-dir", str(data_dir),
                "issue", "myapp.local",
                "--ip", "127.0.0.1",
                "--out", str(out_dir),
            ])
            assert result.exit_code == 0

    def test_issue_shows_fingerprint(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            data_dir = Path(td) / "ca"
            out_dir = Path(td) / "certs"
            runner.invoke(main, ["--data-dir", str(data_dir), "init"])
            result = runner.invoke(main, [
                "--data-dir", str(data_dir),
                "issue", "myapp.local",
                "--out", str(out_dir),
            ])
            assert "Fingerprint:" in result.output

    def test_issued_key_has_secure_permissions(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            data_dir = Path(td) / "ca"
            out_dir = Path(td) / "certs"
            runner.invoke(main, ["--data-dir", str(data_dir), "init"])
            runner.invoke(main, [
                "--data-dir", str(data_dir),
                "issue", "myapp.local",
                "--out", str(out_dir),
            ])
            key_path = out_dir / "key.pem"
            mode = key_path.stat().st_mode
            assert (mode & (stat.S_IRWXG | stat.S_IRWXO)) == 0


class TestImportCaCommand:
    def _write_rsa_ca(self, td: str) -> tuple[Path, Path]:
        """Helper: create RSA CA files in a temp dir."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Corp Root CA"),
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

        cert_path = Path(td) / "corp-ca.pem"
        key_path = Path(td) / "corp-ca-key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        return cert_path, key_path

    def test_import_rsa_ca(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            cert_path, key_path = self._write_rsa_ca(td)
            data_dir = Path(td) / "kalypso"
            result = runner.invoke(main, [
                "--data-dir", str(data_dir),
                "import-ca",
                "--cert", str(cert_path),
                "--key", str(key_path),
            ])
            assert result.exit_code == 0
            assert "External CA imported" in result.output
            assert "RSA" in result.output
            assert (data_dir / "ca-cert.pem").exists()
            assert (data_dir / "ca-key.pem").exists()

    def test_import_then_issue(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            cert_path, key_path = self._write_rsa_ca(td)
            data_dir = Path(td) / "kalypso"
            out_dir = Path(td) / "certs"
            runner.invoke(main, [
                "--data-dir", str(data_dir),
                "import-ca",
                "--cert", str(cert_path),
                "--key", str(key_path),
            ])
            result = runner.invoke(main, [
                "--data-dir", str(data_dir),
                "issue", "myapp.local",
                "--out", str(out_dir),
            ])
            assert result.exit_code == 0
            assert (out_dir / "cert.pem").exists()

    def test_import_refuses_if_ca_exists(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            cert_path, key_path = self._write_rsa_ca(td)
            data_dir = Path(td) / "kalypso"
            runner.invoke(main, ["--data-dir", str(data_dir), "init"])
            result = runner.invoke(main, [
                "--data-dir", str(data_dir),
                "import-ca",
                "--cert", str(cert_path),
                "--key", str(key_path),
            ])
            assert result.exit_code == 1
            assert "already exists" in result.output

    def test_import_rejects_leaf_cert(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            import datetime

            key = ec.generate_private_key(ec.SECP256R1())
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")])
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
            cert_path = Path(td) / "leaf.pem"
            key_path = Path(td) / "leaf-key.pem"
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            data_dir = Path(td) / "kalypso"
            result = runner.invoke(main, [
                "--data-dir", str(data_dir),
                "import-ca",
                "--cert", str(cert_path),
                "--key", str(key_path),
            ])
            assert result.exit_code == 1
            assert "CA:FALSE" in result.output

    def test_import_sets_key_permissions(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            cert_path, key_path = self._write_rsa_ca(td)
            data_dir = Path(td) / "kalypso"
            runner.invoke(main, [
                "--data-dir", str(data_dir),
                "import-ca",
                "--cert", str(cert_path),
                "--key", str(key_path),
            ])
            dest_key = data_dir / "ca-key.pem"
            mode = dest_key.stat().st_mode
            assert (mode & (stat.S_IRWXG | stat.S_IRWXO)) == 0


class TestCaCertCommand:
    def test_prints_ca_cert(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            runner.invoke(main, ["--data-dir", td, "init"])
            result = runner.invoke(main, ["--data-dir", td, "ca-cert"])
            assert result.exit_code == 0
            assert "BEGIN CERTIFICATE" in result.output

    def test_fails_without_init(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            result = runner.invoke(main, ["--data-dir", td, "ca-cert"])
            assert result.exit_code == 1


class TestStatusCommand:
    def test_shows_ca_info(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            runner.invoke(main, ["--data-dir", td, "init"])
            result = runner.invoke(main, ["--data-dir", td, "status"])
            assert result.exit_code == 0
            assert "Fingerprint:" in result.output
            assert "Subject:" in result.output
            assert "Key Security:" in result.output

    def test_shows_secure_key_status(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            runner.invoke(main, ["--data-dir", td, "init"])
            result = runner.invoke(main, ["--data-dir", td, "status"])
            assert "secure" in result.output

    def test_fails_without_init(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as td:
            result = runner.invoke(main, ["--data-dir", td, "status"])
            assert result.exit_code == 1


class TestServeFlags:
    """Test that serve command accepts the auto-inject/trust/reload flags."""

    def test_serve_accepts_no_auto_inject(self):
        runner = CliRunner()
        # Just check the flag is accepted (will fail to start server, but no click error)
        result = runner.invoke(main, ["serve", "--no-auto-inject", "--help"])
        assert result.exit_code == 0

    def test_serve_accepts_no_auto_trust(self):
        runner = CliRunner()
        result = runner.invoke(main, ["serve", "--no-auto-trust", "--help"])
        assert result.exit_code == 0

    def test_serve_accepts_no_auto_reload(self):
        runner = CliRunner()
        result = runner.invoke(main, ["serve", "--no-auto-reload", "--help"])
        assert result.exit_code == 0

    def test_serve_help_shows_flags(self):
        runner = CliRunner()
        result = runner.invoke(main, ["serve", "--help"])
        assert result.exit_code == 0
        assert "--auto-inject" in result.output
        assert "--no-auto-inject" in result.output
        assert "--auto-trust" in result.output
        assert "--no-auto-trust" in result.output
        assert "--auto-reload" in result.output
        assert "--no-auto-reload" in result.output

    def test_serve_help_shows_inject_description(self):
        runner = CliRunner()
        result = runner.invoke(main, ["serve", "--help"])
        assert "Inject certs directly" in result.output
