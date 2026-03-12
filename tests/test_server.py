"""Tests for the Kalypso API server."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from kalypso.ca import CertificateAuthority
from kalypso.server import app, set_ca


@pytest.fixture(autouse=True)
def _reset_ca():
    """Inject a fresh CA for each test."""
    ca = CertificateAuthority.init(organization="Test Server CA")
    set_ca(ca)
    yield
    set_ca(None)


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


class TestHealth:
    def test_health_ok(self, client: TestClient):
        r = client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["ca_initialized"] is True
        assert data["issued_count"] == 0

    def test_health_counts_issued(self, client: TestClient):
        client.post("/certificates", json={"domains": ["a.local"]})
        client.post("/certificates", json={"domains": ["b.local"]})
        r = client.get("/health")
        assert r.json()["issued_count"] == 2


class TestCACertificate:
    def test_get_ca_pem_returns_raw_pem(self, client: TestClient):
        r = client.get("/ca.pem")
        assert r.status_code == 200
        assert "application/x-pem-file" in r.headers["content-type"]
        assert r.text.startswith("-----BEGIN CERTIFICATE-----")

    def test_get_ca_json(self, client: TestClient):
        r = client.get("/ca.json")
        assert r.status_code == 200
        data = r.json()
        assert "BEGIN CERTIFICATE" in data["certificate"]
        assert "fingerprint" in data
        assert "not_before" in data
        assert "not_after" in data
        assert "subject" in data


class TestIssueCertificate:
    def test_issue_basic(self, client: TestClient):
        r = client.post("/certificates", json={"domains": ["myapp.local"]})
        assert r.status_code == 200
        data = r.json()
        assert "BEGIN CERTIFICATE" in data["certificate"]
        assert "BEGIN PRIVATE KEY" in data["private_key"]
        assert data["domains"] == ["myapp.local"]
        assert "not_after" in data
        assert "BEGIN CERTIFICATE" in data["ca_certificate"]

    def test_issue_multiple_domains(self, client: TestClient):
        r = client.post("/certificates", json={
            "domains": ["myapp.local", "*.myapp.local", "api.myapp.local"]
        })
        assert r.status_code == 200
        assert r.json()["domains"] == ["myapp.local", "*.myapp.local", "api.myapp.local"]

    def test_issue_with_custom_hours(self, client: TestClient):
        r = client.post("/certificates", json={"domains": ["myapp.local"], "hours": 4})
        assert r.status_code == 200

    def test_issue_with_ip_addresses(self, client: TestClient):
        r = client.post("/certificates", json={
            "domains": ["myapp.local"],
            "ip_addresses": ["127.0.0.1"],
        })
        assert r.status_code == 200

    def test_issue_empty_domains_rejected(self, client: TestClient):
        r = client.post("/certificates", json={"domains": []})
        assert r.status_code == 422

    def test_issue_zero_hours_rejected(self, client: TestClient):
        r = client.post("/certificates", json={"domains": ["a.local"], "hours": 0})
        assert r.status_code == 422

    def test_issue_negative_hours_rejected(self, client: TestClient):
        r = client.post("/certificates", json={"domains": ["a.local"], "hours": -1})
        assert r.status_code == 422

    def test_issue_exceeding_max_hours_clamped(self, client: TestClient):
        r = client.post("/certificates", json={"domains": ["a.local"], "hours": 168})
        assert r.status_code == 200

    def test_response_includes_ca_cert(self, client: TestClient):
        r = client.post("/certificates", json={"domains": ["myapp.local"]})
        data = r.json()
        ca_r = client.get("/ca.pem")
        assert data["ca_certificate"] == ca_r.text
