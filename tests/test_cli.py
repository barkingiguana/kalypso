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
