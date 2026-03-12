"""Tests for native trust store management."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from kalypso.ca import CertificateAuthority
from kalypso.trust import (
    TrustResult,
    TrustStoreError,
    _run_cmd,
    detect_platform,
    install,
    trust_instructions,
    uninstall,
)


class TestDetectPlatform:
    def test_macos(self):
        with patch("platform.system", return_value="Darwin"):
            assert detect_platform() == "macos"

    def test_linux(self):
        with patch("platform.system", return_value="Linux"):
            assert detect_platform() == "linux"

    def test_windows(self):
        with patch("platform.system", return_value="Windows"):
            assert detect_platform() == "windows"

    def test_unknown_defaults_to_linux(self):
        with patch("platform.system", return_value="FreeBSD"):
            assert detect_platform() == "linux"


class TestTrustResult:
    def test_success_with_stores(self):
        r = TrustResult(success=True, stores_modified=["macOS Keychain"])
        assert r.success is True
        assert len(r.stores_modified) == 1

    def test_failure_with_errors(self):
        r = TrustResult(success=False, errors=["permission denied"])
        assert r.success is False
        assert "permission denied" in r.errors

    def test_defaults(self):
        r = TrustResult(success=False)
        assert r.stores_modified == []
        assert r.errors == []


class TestInstall:
    def test_missing_cert_returns_failure(self):
        result = install(Path("/nonexistent/ca.pem"))
        assert result.success is False
        assert "not found" in result.errors[0]

    def test_delegates_to_platform(self):
        ca = CertificateAuthority.init()
        with tempfile.TemporaryDirectory() as td:
            cert_path = Path(td) / "ca.pem"
            key_path = Path(td) / "key.pem"
            ca.root.save(cert_path, key_path)

            with (
                patch("kalypso.trust.detect_platform", return_value="linux"),
                patch("kalypso.trust._install_linux") as mock_install,
            ):
                mock_install.return_value = TrustResult(success=True, stores_modified=["test"])
                result = install(cert_path)
                assert result.success is True
                mock_install.assert_called_once_with(cert_path)


class TestUninstall:
    def test_missing_cert_returns_failure(self):
        result = uninstall(Path("/nonexistent/ca.pem"))
        assert result.success is False


class TestTrustInstructions:
    def test_returns_instructions_for_all_platforms(self):
        instructions = trust_instructions(Path("/tmp/ca.pem"))
        assert len(instructions) >= 5
        texts = " ".join(instructions)
        assert "macOS" in texts
        assert "Ubuntu" in texts
        assert "Windows" in texts
        assert "Node.js" in texts


class TestRunCmd:
    def test_successful_command(self):
        result = _run_cmd(["echo", "hello"])
        assert "hello" in result.stdout

    def test_failed_command_raises(self):
        with pytest.raises(TrustStoreError):
            _run_cmd(["false"])

    def test_missing_command_raises(self):
        with pytest.raises(TrustStoreError, match="not found"):
            _run_cmd(["nonexistent_command_xyz"])

    def test_uses_clean_environment(self):
        # Verify sensitive env vars are not leaked
        result = _run_cmd(["env"])
        env_output = result.stdout
        assert "KALYPSO" not in env_output  # no app vars leak through
