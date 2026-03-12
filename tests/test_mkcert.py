"""Tests for mkcert integration."""

from __future__ import annotations

from unittest.mock import patch

from kalypso.mkcert import MkcertStatus, find_mkcert


class TestFindMkcert:
    def test_not_available_when_not_installed(self):
        with patch("shutil.which", return_value=None):
            status = find_mkcert()
            assert status.available is False
            assert status.path is None

    def test_available_when_installed(self):
        with (
            patch("shutil.which", return_value="/usr/local/bin/mkcert"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value.stdout = "v1.4.4"
            mock_run.return_value.stderr = ""
            status = find_mkcert()
            assert status.available is True
            assert status.path == "/usr/local/bin/mkcert"
            assert status.version == "v1.4.4"

    def test_handles_subprocess_error(self):
        import subprocess

        with (
            patch("shutil.which", return_value="/usr/local/bin/mkcert"),
            patch("subprocess.run", side_effect=subprocess.SubprocessError),
        ):
            status = find_mkcert()
            assert status.available is False


class TestMkcertStatus:
    def test_status_fields(self):
        status = MkcertStatus(available=True, path="/usr/bin/mkcert", version="v1.4.4")
        assert status.available is True
        assert status.path == "/usr/bin/mkcert"
        assert status.version == "v1.4.4"

    def test_unavailable_defaults(self):
        status = MkcertStatus(available=False)
        assert status.path is None
        assert status.version is None
