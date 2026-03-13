"""Tests for the Docker auto-discovery watcher."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from kalypso.ca import CertificateAuthority
from kalypso.docker_watcher import DockerWatcher, ManagedService


@pytest.fixture()
def ca() -> CertificateAuthority:
    return CertificateAuthority.init(organization="Test Docker CA")


@pytest.fixture()
def watcher(ca: CertificateAuthority) -> DockerWatcher:
    return DockerWatcher(
        ca=ca,
        socket_path="/fake/docker.sock",
    )


@pytest.fixture()
def watcher_no_inject(ca: CertificateAuthority) -> DockerWatcher:
    return DockerWatcher(
        ca=ca,
        socket_path="/fake/docker.sock",
        auto_inject=False,
    )


@pytest.fixture()
def watcher_no_trust(ca: CertificateAuthority) -> DockerWatcher:
    return DockerWatcher(
        ca=ca,
        socket_path="/fake/docker.sock",
        auto_trust=False,
    )


@pytest.fixture()
def watcher_no_reload(ca: CertificateAuthority) -> DockerWatcher:
    return DockerWatcher(
        ca=ca,
        socket_path="/fake/docker.sock",
        auto_reload=False,
    )


class TestParseContainer:
    def test_parses_basic_container(self, watcher: DockerWatcher):
        container = {
            "Id": "abc123",
            "Names": ["/web"],
            "Labels": {"kalypso.domains": "myapp.local"},
            "Image": "nginx:alpine",
        }
        svc = watcher._parse_container(container)
        assert svc is not None
        assert svc.domains == ["myapp.local"]
        assert svc.container_name == "web"
        assert svc.hours == 24
        assert svc.cert_path == "/etc/nginx/ssl/cert.pem"
        assert svc.key_path == "/etc/nginx/ssl/key.pem"

    def test_parses_multiple_domains(self, watcher: DockerWatcher):
        container = {
            "Id": "abc123",
            "Names": ["/web"],
            "Labels": {"kalypso.domains": "myapp.local, *.myapp.local, api.myapp.local"},
            "Image": "nginx:alpine",
        }
        svc = watcher._parse_container(container)
        assert svc.domains == ["myapp.local", "*.myapp.local", "api.myapp.local"]

    def test_ignores_container_without_label(self, watcher: DockerWatcher):
        container = {
            "Id": "abc123",
            "Names": ["/web"],
            "Labels": {},
            "Image": "nginx:alpine",
        }
        assert watcher._parse_container(container) is None

    def test_custom_hours(self, watcher: DockerWatcher):
        container = {
            "Id": "abc123",
            "Names": ["/web"],
            "Labels": {"kalypso.domains": "a.local", "kalypso.hours": "48"},
            "Image": "nginx:alpine",
        }
        svc = watcher._parse_container(container)
        assert svc.hours == 48

    def test_custom_reload(self, watcher: DockerWatcher):
        container = {
            "Id": "abc123",
            "Names": ["/web"],
            "Labels": {
                "kalypso.domains": "a.local",
                "kalypso.reload": "kill -HUP 1",
            },
            "Image": "myimage:latest",
        }
        svc = watcher._parse_container(container)
        assert svc.reload_cmd == ["kill", "-HUP", "1"]

    def test_custom_cert_path(self, watcher: DockerWatcher):
        container = {
            "Id": "abc123",
            "Names": ["/web"],
            "Labels": {
                "kalypso.domains": "a.local",
                "kalypso.cert-path": "/custom/cert.pem",
                "kalypso.key-path": "/custom/key.pem",
                "kalypso.ca-path": "/custom/ca.pem",
            },
            "Image": "nginx:alpine",
        }
        svc = watcher._parse_container(container)
        assert svc.cert_path == "/custom/cert.pem"
        assert svc.key_path == "/custom/key.pem"
        assert svc.ca_path == "/custom/ca.pem"

    def test_image_profile_for_nginx(self, watcher: DockerWatcher):
        container = {
            "Id": "abc123",
            "Names": ["/web"],
            "Labels": {"kalypso.domains": "a.local"},
            "Image": "nginx:alpine",
        }
        svc = watcher._parse_container(container)
        assert svc.cert_path == "/etc/nginx/ssl/cert.pem"
        assert svc.key_path == "/etc/nginx/ssl/key.pem"
        assert svc.reload_cmd == ["nginx", "-s", "reload"]

    def test_image_profile_for_httpd(self, watcher: DockerWatcher):
        container = {
            "Id": "abc123",
            "Names": ["/web"],
            "Labels": {"kalypso.domains": "a.local"},
            "Image": "httpd:2.4",
        }
        svc = watcher._parse_container(container)
        assert svc.cert_path == "/usr/local/apache2/conf/server.crt"
        assert svc.reload_cmd == ["apachectl", "graceful"]

    def test_fallback_for_unknown_image(self, watcher: DockerWatcher):
        container = {
            "Id": "abc123",
            "Names": ["/web"],
            "Labels": {"kalypso.domains": "a.local"},
            "Image": "myapp:latest",
        }
        svc = watcher._parse_container(container)
        assert svc.cert_path == "/etc/ssl/kalypso/cert.pem"
        assert svc.reload_cmd is None

    def test_auto_false_uses_fallback(self, watcher: DockerWatcher):
        container = {
            "Id": "abc123",
            "Names": ["/web"],
            "Labels": {
                "kalypso.domains": "a.local",
                "kalypso.auto": "false",
            },
            "Image": "nginx:alpine",
        }
        svc = watcher._parse_container(container)
        # Should use fallback, not nginx profile
        assert svc.cert_path == "/etc/ssl/kalypso/cert.pem"
        assert svc.reload_cmd is None

    def test_trust_false_label(self, watcher: DockerWatcher):
        container = {
            "Id": "abc123",
            "Names": ["/web"],
            "Labels": {
                "kalypso.domains": "a.local",
                "kalypso.trust": "false",
            },
            "Image": "nginx:alpine",
        }
        svc = watcher._parse_container(container)
        assert svc.inject_trust is False

    def test_trust_default_true(self, watcher: DockerWatcher):
        container = {
            "Id": "abc123",
            "Names": ["/web"],
            "Labels": {"kalypso.domains": "a.local"},
            "Image": "nginx:alpine",
        }
        svc = watcher._parse_container(container)
        assert svc.inject_trust is True


class TestSelfExclusion:
    def test_skips_kalypso_self_label(self, watcher: DockerWatcher):
        container = {
            "Id": "abc123",
            "Names": ["/kalypso"],
            "Labels": {
                "kalypso.domains": "a.local",
                "kalypso.self": "true",
            },
            "Image": "kalypso:latest",
        }
        assert watcher._parse_container(container) is None

    def test_skips_hostname_match(self, watcher: DockerWatcher):
        with patch.dict("os.environ", {"HOSTNAME": "abc123"}):
            container = {
                "Id": "abc123deadbeef",
                "Names": ["/kalypso"],
                "Labels": {"kalypso.domains": "a.local"},
                "Image": "kalypso:latest",
            }
            assert watcher._parse_container(container) is None

    def test_does_not_skip_other_containers(self, watcher: DockerWatcher):
        with patch.dict("os.environ", {"HOSTNAME": "different"}):
            container = {
                "Id": "abc123",
                "Names": ["/web"],
                "Labels": {"kalypso.domains": "a.local"},
                "Image": "nginx:alpine",
            }
            assert watcher._parse_container(container) is not None


class TestAutoInjectOff:
    def test_no_inject_uses_fallback_profile(self, watcher_no_inject: DockerWatcher):
        container = {
            "Id": "abc123",
            "Names": ["/web"],
            "Labels": {"kalypso.domains": "a.local"},
            "Image": "nginx:alpine",
        }
        svc = watcher_no_inject._parse_container(container)
        # auto_inject=False → uses fallback profile
        assert svc.cert_path == "/etc/ssl/kalypso/cert.pem"


class TestAutoReloadOff:
    def test_no_reload_cmd(self, watcher_no_reload: DockerWatcher):
        container = {
            "Id": "abc123",
            "Names": ["/web"],
            "Labels": {"kalypso.domains": "a.local"},
            "Image": "nginx:alpine",
        }
        svc = watcher_no_reload._parse_container(container)
        assert svc.reload_cmd is None


class TestAutoTrustOff:
    def test_inject_trust_false(self, watcher_no_trust: DockerWatcher):
        container = {
            "Id": "abc123",
            "Names": ["/web"],
            "Labels": {"kalypso.domains": "a.local"},
            "Image": "nginx:alpine",
        }
        svc = watcher_no_trust._parse_container(container)
        assert svc.inject_trust is False


class TestServiceName:
    def test_compose_label_preferred(self):
        container = {
            "Id": "abc123",
            "Names": ["/frontend-web-1"],
            "Labels": {"com.docker.compose.service": "web"},
        }
        assert DockerWatcher._service_name(container) == "web"

    def test_strips_replica_suffix(self):
        container = {"Id": "abc", "Names": ["/myproject-web-1"], "Labels": {}}
        assert DockerWatcher._service_name(container) == "web"

    def test_strips_project_prefix(self):
        container = {"Id": "abc", "Names": ["/frontend-web"], "Labels": {}}
        assert DockerWatcher._service_name(container) == "web"

    def test_plain_name_unchanged(self):
        container = {"Id": "abc", "Names": ["/web"], "Labels": {}}
        assert DockerWatcher._service_name(container) == "web"

    def test_fallback_to_container_id(self):
        container = {"Id": "abc123deadbeef", "Names": [], "Labels": {}}
        assert DockerWatcher._service_name(container) == "abc123deadbe"

    def test_complex_compose_name(self):
        container = {"Id": "abc", "Names": ["/shared-ca-frontend-web-1"], "Labels": {}}
        assert DockerWatcher._service_name(container) == "web"


class TestInjectFiles:
    def test_builds_and_sends_tar(self, watcher: DockerWatcher):
        svc = ManagedService(
            container_id="abc123",
            container_name="web",
            domains=["a.local"],
            hours=24,
            reload_cmd=None,
            cert_path="/etc/nginx/ssl/cert.pem",
            key_path="/etc/nginx/ssl/key.pem",
            ca_path="/etc/nginx/ssl/ca.pem",
        )
        files = {
            "/etc/nginx/ssl/cert.pem": b"CERT",
            "/etc/nginx/ssl/key.pem": b"KEY",
        }

        # Mock the HTTP connection
        with patch("kalypso.docker_watcher.UnixHTTPConnection") as MockConn:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.read.return_value = b""
            MockConn.return_value.getresponse.return_value = mock_resp

            ok = watcher._inject_files(svc, files)

        assert ok is True
        MockConn.return_value.request.assert_called_once()
        call_args = MockConn.return_value.request.call_args
        assert call_args[0][0] == "PUT"
        assert "/archive" in call_args[0][1]
        # Verify it's a valid tar
        tar_data = call_args[1].get("body") or call_args[0][2]
        tar = tarfile.open(fileobj=io.BytesIO(tar_data), mode="r:gz")
        assert "etc/nginx/ssl/cert.pem" in tar.getnames()

    def test_returns_false_on_failure(self, watcher: DockerWatcher):
        svc = ManagedService(
            container_id="abc123",
            container_name="web",
            domains=["a.local"],
            hours=24,
            reload_cmd=None,
            cert_path="/etc/nginx/ssl/cert.pem",
            key_path="/etc/nginx/ssl/key.pem",
            ca_path="/etc/nginx/ssl/ca.pem",
        )

        with patch("kalypso.docker_watcher.UnixHTTPConnection") as MockConn:
            mock_resp = MagicMock()
            mock_resp.status = 500
            mock_resp.read.return_value = b"error"
            MockConn.return_value.getresponse.return_value = mock_resp

            ok = watcher._inject_files(svc, {"/a": b"X"})

        assert ok is False


class TestDetectBaseOS:
    def test_debian(self, watcher: DockerWatcher):
        with patch.object(watcher, "_exec_in_container", return_value=(True, 'ID=debian\nVERSION_ID="12"')):
            assert watcher._detect_base_os("abc") == "debian"

    def test_ubuntu(self, watcher: DockerWatcher):
        with patch.object(watcher, "_exec_in_container", return_value=(True, 'ID=ubuntu\nVERSION_ID="22.04"')):
            assert watcher._detect_base_os("abc") == "debian"

    def test_alpine(self, watcher: DockerWatcher):
        with patch.object(watcher, "_exec_in_container", return_value=(True, 'ID=alpine\nVERSION_ID=3.19')):
            assert watcher._detect_base_os("abc") == "debian"

    def test_fedora(self, watcher: DockerWatcher):
        with patch.object(watcher, "_exec_in_container", return_value=(True, 'ID=fedora\nVERSION_ID=39')):
            assert watcher._detect_base_os("abc") == "rhel"

    def test_rhel(self, watcher: DockerWatcher):
        with patch.object(watcher, "_exec_in_container", return_value=(True, 'ID="rhel"\nVERSION_ID="9"')):
            assert watcher._detect_base_os("abc") == "rhel"

    def test_unknown_defaults_to_debian(self, watcher: DockerWatcher):
        with patch.object(watcher, "_exec_in_container", return_value=(True, 'ID=something\nVERSION_ID=1')):
            assert watcher._detect_base_os("abc") == "debian"

    def test_exec_failure_returns_none(self, watcher: DockerWatcher):
        with patch.object(watcher, "_exec_in_container", return_value=(False, "")):
            assert watcher._detect_base_os("abc") is None


class TestIssueForService:
    def test_injects_certs_when_auto_inject(self, watcher: DockerWatcher):
        svc = ManagedService(
            container_id="abc123",
            container_name="web",
            domains=["myapp.local"],
            hours=24,
            reload_cmd=None,
            cert_path="/etc/nginx/ssl/cert.pem",
            key_path="/etc/nginx/ssl/key.pem",
            ca_path="/etc/nginx/ssl/ca.pem",
        )

        with patch.object(watcher, "_inject_files", return_value=True) as mock_inject, \
             patch.object(watcher, "_inject_ca_trust") as mock_trust:
            watcher._issue_for_service(svc)

        mock_inject.assert_called_once()
        files_arg = mock_inject.call_args[0][1]
        assert "/etc/nginx/ssl/cert.pem" in files_arg
        assert "/etc/nginx/ssl/key.pem" in files_arg
        assert "/etc/nginx/ssl/ca.pem" in files_arg
        mock_trust.assert_called_once()
        assert svc.last_issued > 0.0

    def test_skips_inject_when_auto_inject_off(self, watcher_no_inject: DockerWatcher):
        svc = ManagedService(
            container_id="abc123",
            container_name="web",
            domains=["myapp.local"],
            hours=24,
            reload_cmd=None,
            cert_path="/etc/ssl/kalypso/cert.pem",
            key_path="/etc/ssl/kalypso/key.pem",
            ca_path="/etc/ssl/kalypso/ca.pem",
        )

        with patch.object(watcher_no_inject, "_inject_files") as mock_inject, \
             patch.object(watcher_no_inject, "_inject_ca_trust") as mock_trust:
            watcher_no_inject._issue_for_service(svc)

        mock_inject.assert_not_called()
        mock_trust.assert_not_called()
        assert svc.last_issued > 0.0

    def test_reloads_when_auto_reload(self, watcher: DockerWatcher):
        svc = ManagedService(
            container_id="abc123",
            container_name="web",
            domains=["myapp.local"],
            hours=24,
            reload_cmd=["nginx", "-s", "reload"],
            cert_path="/etc/nginx/ssl/cert.pem",
            key_path="/etc/nginx/ssl/key.pem",
            ca_path="/etc/nginx/ssl/ca.pem",
        )

        with patch.object(watcher, "_inject_files", return_value=True), \
             patch.object(watcher, "_inject_ca_trust"), \
             patch.object(watcher, "_exec_in_container", return_value=(True, "")) as mock_exec:
            watcher._issue_for_service(svc)

        mock_exec.assert_called_once_with("abc123", ["nginx", "-s", "reload"])

    def test_no_reload_when_auto_reload_off(self, watcher_no_reload: DockerWatcher):
        svc = ManagedService(
            container_id="abc123",
            container_name="web",
            domains=["myapp.local"],
            hours=24,
            reload_cmd=None,  # auto_reload=False means _parse_container won't set this
            cert_path="/etc/nginx/ssl/cert.pem",
            key_path="/etc/nginx/ssl/key.pem",
            ca_path="/etc/nginx/ssl/ca.pem",
        )

        with patch.object(watcher_no_reload, "_inject_files", return_value=True), \
             patch.object(watcher_no_reload, "_inject_ca_trust"), \
             patch.object(watcher_no_reload, "_exec_in_container") as mock_exec:
            watcher_no_reload._issue_for_service(svc)

        mock_exec.assert_not_called()
