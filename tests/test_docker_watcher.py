"""Tests for the Docker auto-discovery watcher."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from kalypso.ca import CertificateAuthority
from kalypso.docker_watcher import DockerWatcher, ManagedService


@pytest.fixture()
def ca() -> CertificateAuthority:
    return CertificateAuthority.init(organization="Test Docker CA")


@pytest.fixture()
def watcher(ca: CertificateAuthority, tmp_path: Path) -> DockerWatcher:
    return DockerWatcher(
        ca=ca,
        socket_path="/fake/docker.sock",
        certs_root=tmp_path / "certs",
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

    def test_custom_cert_dir(self, watcher: DockerWatcher):
        container = {
            "Id": "abc123",
            "Names": ["/web"],
            "Labels": {
                "kalypso.domains": "a.local",
                "kalypso.cert_dir": "web-certs",
            },
            "Image": "nginx:alpine",
        }
        svc = watcher._parse_container(container)
        assert svc.cert_dir == watcher.certs_root / "web-certs"


class TestAutoDetectReload:
    def test_nginx(self, watcher: DockerWatcher):
        assert watcher._detect_reload_cmd("nginx:alpine") == ["nginx", "-s", "reload"]

    def test_nginx_prefix(self, watcher: DockerWatcher):
        assert watcher._detect_reload_cmd("library/nginx:1.27") == ["nginx", "-s", "reload"]

    def test_httpd(self, watcher: DockerWatcher):
        assert watcher._detect_reload_cmd("httpd:latest") == ["apachectl", "graceful"]

    def test_haproxy(self, watcher: DockerWatcher):
        assert watcher._detect_reload_cmd("haproxy:2.9") == ["kill", "-USR2", "1"]

    def test_caddy(self, watcher: DockerWatcher):
        cmd = watcher._detect_reload_cmd("caddy:2")
        assert cmd is not None
        assert "caddy" in cmd[0]

    def test_traefik_no_reload_needed(self, watcher: DockerWatcher):
        assert watcher._detect_reload_cmd("traefik:v3.0") is None

    def test_unknown_image(self, watcher: DockerWatcher):
        assert watcher._detect_reload_cmd("myapp:latest") is None


class TestIssueForService:
    def test_writes_cert_files(self, watcher: DockerWatcher, tmp_path: Path):
        cert_dir = tmp_path / "out"
        svc = ManagedService(
            container_id="abc123",
            container_name="web",
            domains=["myapp.local"],
            cert_dir=cert_dir,
            hours=24,
            reload_cmd=None,
        )
        watcher._issue_for_service(svc)

        assert (cert_dir / "cert.pem").exists()
        assert (cert_dir / "key.pem").exists()
        assert (cert_dir / "ca.pem").exists()
        assert (cert_dir / "fullchain.pem").exists()
        assert "BEGIN CERTIFICATE" in (cert_dir / "cert.pem").read_text()
        assert "BEGIN PRIVATE KEY" in (cert_dir / "key.pem").read_text()

    def test_updates_last_issued(self, watcher: DockerWatcher, tmp_path: Path):
        svc = ManagedService(
            container_id="abc123",
            container_name="web",
            domains=["myapp.local"],
            cert_dir=tmp_path / "out",
            hours=24,
            reload_cmd=None,
        )
        assert svc.last_issued == 0.0
        watcher._issue_for_service(svc)
        assert svc.last_issued > 0.0


class TestServiceName:
    def test_compose_label_preferred(self, watcher: DockerWatcher):
        container = {
            "Id": "abc123",
            "Names": ["/frontend-web-1"],
            "Labels": {"com.docker.compose.service": "web"},
        }
        assert DockerWatcher._service_name(container) == "web"

    def test_strips_replica_suffix(self, watcher: DockerWatcher):
        container = {"Id": "abc", "Names": ["/myproject-web-1"], "Labels": {}}
        assert DockerWatcher._service_name(container) == "web"

    def test_strips_project_prefix(self, watcher: DockerWatcher):
        container = {"Id": "abc", "Names": ["/frontend-web"], "Labels": {}}
        assert DockerWatcher._service_name(container) == "web"

    def test_plain_name_unchanged(self, watcher: DockerWatcher):
        container = {"Id": "abc", "Names": ["/web"], "Labels": {}}
        assert DockerWatcher._service_name(container) == "web"

    def test_fallback_to_container_id(self, watcher: DockerWatcher):
        container = {"Id": "abc123deadbeef", "Names": [], "Labels": {}}
        assert DockerWatcher._service_name(container) == "abc123deadbe"

    def test_complex_compose_name(self, watcher: DockerWatcher):
        container = {"Id": "abc", "Names": ["/shared-ca-frontend-web-1"], "Labels": {}}
        assert DockerWatcher._service_name(container) == "web"


class TestHandleMultipleServices:
    def test_single_service_uses_root(self, watcher: DockerWatcher):
        svc = ManagedService(
            container_id="a",
            container_name="web",
            domains=["a.local"],
            cert_dir=watcher.certs_root,
            hours=24,
            reload_cmd=None,
        )
        watcher._handle_multiple_services([svc])
        assert svc.cert_dir == watcher.certs_root

    def test_multiple_services_get_subdirs(self, watcher: DockerWatcher):
        svc1 = ManagedService(
            container_id="a",
            container_name="frontend-web-1",
            domains=["web.local"],
            cert_dir=watcher.certs_root,
            hours=24,
            reload_cmd=None,
        )
        svc2 = ManagedService(
            container_id="b",
            container_name="backend-api-1",
            domains=["api.local"],
            cert_dir=watcher.certs_root,
            hours=24,
            reload_cmd=None,
        )
        containers = [
            {"Id": "a", "Names": ["/frontend-web-1"], "Labels": {"com.docker.compose.service": "web"}},
            {"Id": "b", "Names": ["/backend-api-1"], "Labels": {"com.docker.compose.service": "api"}},
        ]
        watcher._handle_multiple_services([svc1, svc2], containers)
        assert svc1.cert_dir == watcher.certs_root / "web"
        assert svc2.cert_dir == watcher.certs_root / "api"

    def test_fallback_to_container_name_without_raw(self, watcher: DockerWatcher):
        """When no raw container dicts are provided, falls back to container_name."""
        svc1 = ManagedService(
            container_id="a",
            container_name="web",
            domains=["web.local"],
            cert_dir=watcher.certs_root,
            hours=24,
            reload_cmd=None,
        )
        svc2 = ManagedService(
            container_id="b",
            container_name="api",
            domains=["api.local"],
            cert_dir=watcher.certs_root,
            hours=24,
            reload_cmd=None,
        )
        watcher._handle_multiple_services([svc1, svc2])
        assert svc1.cert_dir == watcher.certs_root / "web"
        assert svc2.cert_dir == watcher.certs_root / "api"
