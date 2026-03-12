"""Tests for the Kalypso sidecar module."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from kalypso.sidecar import _issue_and_write, _run_reload_cmd, _wait_for_server


class TestIssueAndWrite:
    def test_writes_cert_files(self, tmp_path: Path):
        cert_dir = tmp_path / "certs"
        fake_response = {
            "certificate": "-----BEGIN CERTIFICATE-----\nfake-cert\n-----END CERTIFICATE-----\n",
            "private_key": "-----BEGIN PRIVATE KEY-----\nfake-key\n-----END PRIVATE KEY-----\n",
            "ca_certificate": "-----BEGIN CERTIFICATE-----\nfake-ca\n-----END CERTIFICATE-----\n",
            "domains": ["myapp.local"],
            "not_after": "2025-01-02T12:00:00Z",
        }
        with patch("kalypso.sidecar.httpx") as mock_httpx:
            mock_response = mock_httpx.post.return_value
            mock_response.json.return_value = fake_response

            sleep_time = _issue_and_write(
                "http://fake:8200",
                ["myapp.local"],
                cert_dir,
                24,
            )

        assert (cert_dir / "cert.pem").read_text() == fake_response["certificate"]
        assert (cert_dir / "key.pem").read_text() == fake_response["private_key"]
        assert (cert_dir / "ca.pem").read_text() == fake_response["ca_certificate"]
        assert (cert_dir / "fullchain.pem").exists()
        # 50% of 24h in seconds
        assert sleep_time == 24 * 3600 * 0.5

    def test_creates_cert_dir(self, tmp_path: Path):
        cert_dir = tmp_path / "deep" / "nested" / "certs"
        fake_response = {
            "certificate": "cert",
            "private_key": "key",
            "ca_certificate": "ca",
            "domains": ["a.local"],
            "not_after": "2025-01-02T12:00:00Z",
        }
        with patch("kalypso.sidecar.httpx") as mock_httpx:
            mock_httpx.post.return_value.json.return_value = fake_response
            _issue_and_write("http://fake:8200", ["a.local"], cert_dir, 24)

        assert cert_dir.is_dir()


class TestRunReloadCmd:
    def test_successful_command(self):
        with patch("kalypso.sidecar.subprocess.run") as mock_run:
            _run_reload_cmd("echo ok")
            mock_run.assert_called_once()

    def test_failed_command_does_not_raise(self):
        import subprocess

        with patch(
            "kalypso.sidecar.subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "fail", stderr="error"),
        ):
            # Should not raise
            _run_reload_cmd("fail")


class TestWaitForServer:
    def test_raises_on_timeout(self):
        with patch("kalypso.sidecar.httpx") as mock_httpx:
            mock_httpx.HTTPError = Exception
            mock_httpx.get.side_effect = Exception("connection refused")
            with pytest.raises(RuntimeError, match="not ready"):
                _wait_for_server("http://fake:8200", timeout=1)
