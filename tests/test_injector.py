"""Tests for tar archive builder."""

from __future__ import annotations

import io
import tarfile

from kalypso.injector import build_tar


class TestBuildTar:
    def test_produces_valid_tar(self):
        data = build_tar({"/etc/ssl/cert.pem": b"CERT"})
        tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
        members = tar.getnames()
        assert "etc/ssl/cert.pem" in members

    def test_correct_contents(self):
        files = {
            "/etc/ssl/cert.pem": b"CERT-DATA",
            "/etc/ssl/key.pem": b"KEY-DATA",
        }
        data = build_tar(files, key_paths=frozenset(["/etc/ssl/key.pem"]))
        tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")

        cert = tar.extractfile("etc/ssl/cert.pem")
        assert cert is not None
        assert cert.read() == b"CERT-DATA"

        key = tar.extractfile("etc/ssl/key.pem")
        assert key is not None
        assert key.read() == b"KEY-DATA"

    def test_key_permissions(self):
        files = {
            "/etc/ssl/cert.pem": b"CERT",
            "/etc/ssl/key.pem": b"KEY",
        }
        data = build_tar(files, key_paths=frozenset(["/etc/ssl/key.pem"]))
        tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")

        cert_info = tar.getmember("etc/ssl/cert.pem")
        assert cert_info.mode == 0o644

        key_info = tar.getmember("etc/ssl/key.pem")
        assert key_info.mode == 0o600

    def test_default_permissions_without_key_paths(self):
        data = build_tar({"/a.pem": b"X"})
        tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
        assert tar.getmember("a.pem").mode == 0o644

    def test_empty_files(self):
        data = build_tar({})
        tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
        assert tar.getnames() == []

    def test_multiple_files(self):
        files = {
            "/a/cert.pem": b"C",
            "/a/key.pem": b"K",
            "/a/ca.pem": b"CA",
            "/a/fullchain.pem": b"FC",
        }
        data = build_tar(files, key_paths=frozenset(["/a/key.pem"]))
        tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
        assert len(tar.getnames()) == 4
