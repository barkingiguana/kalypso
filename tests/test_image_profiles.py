"""Tests for image profile auto-detection."""

from __future__ import annotations

import pytest

from kalypso.image_profiles import FALLBACK_PROFILE, ImageProfile, get_profile


class TestStripAndExactMatch:
    def test_nginx_plain(self):
        p = get_profile("nginx")
        assert p.cert_path == "/etc/nginx/ssl/cert.pem"
        assert p.reload_cmd == ["nginx", "-s", "reload"]

    def test_nginx_with_tag(self):
        p = get_profile("nginx:alpine")
        assert p.cert_path == "/etc/nginx/ssl/cert.pem"

    def test_nginx_with_registry(self):
        p = get_profile("docker.io/library/nginx:1.27")
        assert p.cert_path == "/etc/nginx/ssl/cert.pem"

    def test_httpd(self):
        p = get_profile("httpd:latest")
        assert p.cert_path == "/usr/local/apache2/conf/server.crt"
        assert p.reload_cmd == ["apachectl", "graceful"]

    def test_apache(self):
        p = get_profile("apache:2.4")
        assert p.cert_path == "/usr/local/apache2/conf/server.crt"

    def test_haproxy(self):
        p = get_profile("haproxy:2.9")
        assert p.cert_path == "/usr/local/etc/haproxy/certs/cert.pem"
        assert p.reload_cmd == ["kill", "-USR2", "1"]

    def test_caddy(self):
        p = get_profile("caddy:2")
        assert p.cert_path == "/etc/caddy/certs/cert.pem"
        assert p.reload_cmd is None

    def test_traefik(self):
        p = get_profile("traefik:v3.0")
        assert p.cert_path == "/etc/traefik/certs/cert.pem"
        assert p.reload_cmd is None


class TestContainsMatch:
    def test_custom_nginx_image(self):
        p = get_profile("ghcr.io/myorg/custom-nginx:v2")
        assert p.cert_path == "/etc/nginx/ssl/cert.pem"

    def test_bitnami_apache(self):
        p = get_profile("bitnami/apache:latest")
        assert p.cert_path == "/usr/local/apache2/conf/server.crt"

    def test_nginx_proxy(self):
        p = get_profile("nginxproxy/nginx-proxy:latest")
        assert p.cert_path == "/etc/nginx/ssl/cert.pem"


class TestFallback:
    def test_node(self):
        p = get_profile("node:20-alpine")
        assert p == FALLBACK_PROFILE

    def test_python(self):
        p = get_profile("python:3.12-slim")
        assert p == FALLBACK_PROFILE

    def test_go(self):
        p = get_profile("golang:1.22")
        assert p == FALLBACK_PROFILE

    def test_custom_image(self):
        p = get_profile("mycompany/myapp:latest")
        assert p == FALLBACK_PROFILE

    def test_fallback_paths(self):
        p = get_profile("myapp:latest")
        assert p.cert_path == "/etc/ssl/kalypso/cert.pem"
        assert p.key_path == "/etc/ssl/kalypso/key.pem"
        assert p.ca_path == "/etc/ssl/kalypso/ca.pem"
        assert p.reload_cmd is None


class TestProfileIsFrozen:
    def test_cannot_mutate(self):
        p = get_profile("nginx")
        with pytest.raises(AttributeError):
            p.cert_path = "/other"  # type: ignore[misc]
