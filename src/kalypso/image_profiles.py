"""Image profiles — auto-detect cert paths and reload commands by container image.

Maps well-known image name patterns to the cert/key file paths and reload
commands used by that server.  The ``get_profile`` function is the main
entry point: pass a Docker image string (e.g. ``"nginx:alpine"``) and get
back an ``ImageProfile`` with sensible defaults.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ImageProfile:
    """Cert/key paths and reload command for a container image."""

    cert_path: str
    key_path: str
    ca_path: str
    reload_cmd: list[str] | None


# Ordered list of (compiled regex, profile).  First match wins.
_PROFILES: list[tuple[re.Pattern[str], ImageProfile]] = [
    (
        re.compile(r"^nginx$"),
        ImageProfile(
            cert_path="/etc/nginx/ssl/cert.pem",
            key_path="/etc/nginx/ssl/key.pem",
            ca_path="/etc/nginx/ssl/ca.pem",
            reload_cmd=["nginx", "-s", "reload"],
        ),
    ),
    (
        re.compile(r"^httpd$|^apache$"),
        ImageProfile(
            cert_path="/usr/local/apache2/conf/server.crt",
            key_path="/usr/local/apache2/conf/server.key",
            ca_path="/usr/local/apache2/conf/server-ca.crt",
            reload_cmd=["apachectl", "graceful"],
        ),
    ),
    (
        re.compile(r"^haproxy$"),
        ImageProfile(
            cert_path="/usr/local/etc/haproxy/certs/cert.pem",
            key_path="/usr/local/etc/haproxy/certs/key.pem",
            ca_path="/usr/local/etc/haproxy/certs/ca.pem",
            reload_cmd=["kill", "-USR2", "1"],
        ),
    ),
    (
        re.compile(r"^caddy$"),
        ImageProfile(
            cert_path="/etc/caddy/certs/cert.pem",
            key_path="/etc/caddy/certs/key.pem",
            ca_path="/etc/caddy/certs/ca.pem",
            reload_cmd=None,  # Caddy watches files
        ),
    ),
    (
        re.compile(r"^traefik$"),
        ImageProfile(
            cert_path="/etc/traefik/certs/cert.pem",
            key_path="/etc/traefik/certs/key.pem",
            ca_path="/etc/traefik/certs/ca.pem",
            reload_cmd=None,  # Traefik watches files
        ),
    ),
]

# Contains-match: image name *contains* this string → use this profile.
_CONTAINS_PROFILES: list[tuple[str, ImageProfile]] = [
    ("nginx", _PROFILES[0][1]),
    ("httpd", _PROFILES[1][1]),
    ("apache", _PROFILES[1][1]),
    ("haproxy", _PROFILES[2][1]),
    ("caddy", _PROFILES[3][1]),
    ("traefik", _PROFILES[4][1]),
]

FALLBACK_PROFILE = ImageProfile(
    cert_path="/etc/ssl/kalypso/cert.pem",
    key_path="/etc/ssl/kalypso/key.pem",
    ca_path="/etc/ssl/kalypso/ca.pem",
    reload_cmd=None,
)


def _strip_image(image: str) -> str:
    """Strip registry prefix and tag from a Docker image string.

    ``"ghcr.io/org/nginx:1.27-alpine"`` → ``"nginx"``
    """
    # Remove tag / digest
    name = image.split("@")[0].split(":")[0]
    # Take the last path component (strips registry + org)
    return name.rsplit("/", 1)[-1].lower()


def get_profile(image: str) -> ImageProfile:
    """Return the best-matching ``ImageProfile`` for *image*.

    Matching priority:
    1. Exact match on the stripped image name
    2. Contains match (image name contains a known pattern)
    3. Fallback generic profile
    """
    stripped = _strip_image(image)

    # 1. Exact match
    for pattern, profile in _PROFILES:
        if pattern.fullmatch(stripped):
            return profile

    # 2. Contains match
    for needle, profile in _CONTAINS_PROFILES:
        if needle in stripped:
            return profile

    # 3. Fallback
    return FALLBACK_PROFILE
