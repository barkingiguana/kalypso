"""Docker auto-discovery — watches for containers with kalypso.* labels.

When a container has a `kalypso.domains` label, Kalypso automatically:
1. Issues a cert for those domains
2. Injects cert files directly into the container (no shared volumes needed)
3. Optionally injects the CA into the container's system trust store
4. Sends a reload signal to the container (auto-detected or explicit)
5. Renews before expiry

Supported labels:
    kalypso.domains     Comma-separated domains (required)
    kalypso.cert-path   Override cert path inside container
    kalypso.key-path    Override key path inside container
    kalypso.ca-path     Override CA cert path inside container
    kalypso.reload      Reload command (auto-detected for nginx/apache/haproxy)
    kalypso.hours       Cert lifetime in hours (default: 24)
    kalypso.trust       "false" to skip CA trust store injection for this container
    kalypso.auto        "false" to disable image-based auto-detection

Uses the Docker Engine API over the Unix socket. No docker-py dependency.
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import socket
import threading
import time
import urllib.parse
from dataclasses import dataclass, field

from kalypso.ca import CertificateAuthority
from kalypso.image_profiles import FALLBACK_PROFILE, get_profile
from kalypso.injector import build_tar

logger = logging.getLogger("kalypso.docker")

DEFAULT_HOURS = 24
DOCKER_API_VERSION = "v1.41"


class UnixHTTPConnection(http.client.HTTPConnection):
    """HTTP connection over a Unix domain socket."""

    def __init__(self, socket_path: str, timeout: int = 30):
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self._socket_path)
        self.sock.settimeout(self.timeout)


@dataclass
class ManagedService:
    """A container that Kalypso is managing certs for."""

    container_id: str
    container_name: str
    domains: list[str]
    hours: int
    reload_cmd: list[str] | None
    cert_path: str
    key_path: str
    ca_path: str
    inject_trust: bool = True
    last_issued: float = 0.0


@dataclass
class DockerWatcher:
    """Watches Docker for containers with kalypso.* labels."""

    ca: CertificateAuthority
    socket_path: str = "/var/run/docker.sock"
    auto_inject: bool = True
    auto_trust: bool = True
    auto_reload: bool = True
    _services: dict[str, ManagedService] = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def _request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        content_type: str = "application/json",
        timeout: int = 30,
    ) -> tuple[int, dict | list | str]:
        """Make a request to the Docker Engine API."""
        conn = UnixHTTPConnection(self.socket_path, timeout=timeout)
        headers = {}
        if body:
            headers["Content-Type"] = content_type
        conn.request(method, f"/{DOCKER_API_VERSION}{path}", body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode()
        conn.close()
        try:
            return resp.status, json.loads(data)
        except json.JSONDecodeError:
            return resp.status, data

    def _exec_in_container(self, container_id: str, cmd: list[str]) -> tuple[bool, str]:
        """Execute a command inside a container via Docker exec API.

        Returns ``(success, output)``."""
        body = json.dumps({"Cmd": cmd, "AttachStdout": True, "AttachStderr": True}).encode()
        status, data = self._request("POST", f"/containers/{container_id}/exec", body=body)
        if status != 201:
            logger.warning("Failed to create exec in %s: %s", container_id[:12], data)
            return False, ""

        exec_id = data["Id"]

        # Start exec and capture output
        start_body = json.dumps({"Detach": False}).encode()
        conn = UnixHTTPConnection(self.socket_path, timeout=30)
        conn.request(
            "POST",
            f"/{DOCKER_API_VERSION}/exec/{exec_id}/start",
            body=start_body,
            headers={"Content-Type": "application/json"},
        )
        resp = conn.getresponse()
        output = resp.read().decode(errors="replace")
        conn.close()

        # Check exec result
        status, result = self._request("GET", f"/exec/{exec_id}/json")
        if status == 200 and result.get("ExitCode", 1) == 0:
            return True, output
        logger.warning("Exec in %s exited %s", container_id[:12], result.get("ExitCode"))
        return False, output

    def _is_self(self, container: dict) -> bool:
        """Return True if this container is the Kalypso instance itself."""
        labels = container.get("Labels", {})
        if labels.get("kalypso.self", "").lower() == "true":
            return True
        # Also check HOSTNAME match
        my_hostname = os.environ.get("HOSTNAME", "")
        if my_hostname and container.get("Id", "").startswith(my_hostname):
            return True
        return False

    def _parse_container(self, container: dict) -> ManagedService | None:
        """Parse a container's labels into a ManagedService."""
        labels = container.get("Labels", {})
        domains_str = labels.get("kalypso.domains", "")
        if not domains_str:
            return None

        domains = [d.strip() for d in domains_str.split(",") if d.strip()]
        if not domains:
            return None

        if self._is_self(container):
            logger.debug("Skipping self: %s", container.get("Id", "")[:12])
            return None

        container_id = container.get("Id", "")
        names = container.get("Names", [])
        name = names[0].lstrip("/") if names else container_id[:12]

        image = container.get("Image", "")
        hours = int(labels.get("kalypso.hours", str(DEFAULT_HOURS)))

        # Determine cert/key/ca paths: label overrides > image profile > fallback
        auto_detect = labels.get("kalypso.auto", "").lower() != "false"
        if auto_detect and self.auto_inject:
            profile = get_profile(image)
        else:
            profile = FALLBACK_PROFILE

        cert_path = labels.get("kalypso.cert-path", "").strip() or profile.cert_path
        key_path = labels.get("kalypso.key-path", "").strip() or profile.key_path
        ca_path = labels.get("kalypso.ca-path", "").strip() or profile.ca_path

        # Reload command: explicit label > profile > none
        reload_cmd: list[str] | None = None
        if self.auto_reload:
            reload_label = labels.get("kalypso.reload", "").strip()
            if reload_label:
                reload_cmd = reload_label.split()
            elif auto_detect:
                reload_cmd = profile.reload_cmd

        # Trust store injection
        inject_trust = self.auto_trust and labels.get("kalypso.trust", "").lower() != "false"

        return ManagedService(
            container_id=container_id,
            container_name=name,
            domains=domains,
            hours=hours,
            reload_cmd=reload_cmd,
            cert_path=cert_path,
            key_path=key_path,
            ca_path=ca_path,
            inject_trust=inject_trust,
        )

    @staticmethod
    def _service_name(container: dict) -> str:
        """Extract a clean service name from a container.

        Prefers the Docker Compose ``com.docker.compose.service`` label.
        Falls back to stripping the Compose ``{project}-{service}-{N}``
        pattern from the container name.
        """
        labels = container.get("Labels", {})
        compose_svc = labels.get("com.docker.compose.service", "").strip()
        if compose_svc:
            return compose_svc

        names = container.get("Names", [])
        raw = names[0].lstrip("/") if names else container.get("Id", "")[:12]

        import re

        m = re.match(r"^(.+?)-(\d+)$", raw)
        if m:
            raw = m.group(1)
        if "-" in raw:
            raw = raw.rsplit("-", 1)[-1]

        return raw

    def _inject_files(self, svc: ManagedService, files: dict[str, bytes]) -> bool:
        """Inject files into a container via Docker archive API."""
        key_paths = frozenset([svc.key_path])
        tar_data = build_tar(files, key_paths=key_paths)

        path_param = urllib.parse.quote("/", safe="")
        conn = UnixHTTPConnection(self.socket_path, timeout=30)
        conn.request(
            "PUT",
            f"/{DOCKER_API_VERSION}/containers/{svc.container_id}/archive?path={path_param}",
            body=tar_data,
            headers={"Content-Type": "application/x-tar"},
        )
        resp = conn.getresponse()
        resp.read()
        conn.close()

        if resp.status == 200:
            return True
        logger.warning(
            "Failed to inject files into %s: HTTP %d",
            svc.container_name,
            resp.status,
        )
        return False

    def _detect_base_os(self, container_id: str) -> str | None:
        """Probe the container OS by reading /etc/os-release.

        Returns ``"debian"``, ``"rhel"``, or ``None``.
        """
        ok, output = self._exec_in_container(container_id, ["cat", "/etc/os-release"])
        if not ok:
            return None
        output_lower = output.lower()
        if any(d in output_lower for d in ("debian", "ubuntu", "alpine")):
            return "debian"
        if any(d in output_lower for d in ("rhel", "fedora", "centos", "rocky", "alma")):
            return "rhel"
        # Default to debian-style (most common Docker base)
        return "debian"

    def _inject_ca_trust(self, svc: ManagedService, ca_pem: bytes) -> None:
        """Inject the CA into the container's system trust store."""
        if not svc.inject_trust:
            return

        base_os = self._detect_base_os(svc.container_id)

        if base_os == "rhel":
            ca_dest = "/etc/pki/ca-trust/source/anchors/kalypso-dev-ca.pem"
            update_cmd = ["update-ca-trust"]
        else:
            # Debian/Ubuntu/Alpine (default)
            ca_dest = "/usr/local/share/ca-certificates/kalypso-dev-ca.crt"
            update_cmd = ["update-ca-certificates"]

        # Inject the CA cert file
        tar_data = build_tar({ca_dest: ca_pem})
        path_param = urllib.parse.quote("/", safe="")
        conn = UnixHTTPConnection(self.socket_path, timeout=30)
        conn.request(
            "PUT",
            f"/{DOCKER_API_VERSION}/containers/{svc.container_id}/archive?path={path_param}",
            body=tar_data,
            headers={"Content-Type": "application/x-tar"},
        )
        resp = conn.getresponse()
        resp.read()
        conn.close()

        if resp.status != 200:
            logger.warning(
                "Failed to inject CA into %s: HTTP %d",
                svc.container_name,
                resp.status,
            )
            return

        # Run the update command
        ok, _ = self._exec_in_container(svc.container_id, update_cmd)
        if ok:
            logger.info("CA trusted in %s (%s)", svc.container_name, base_os or "debian")
        else:
            # Try the other style as fallback
            if base_os != "rhel":
                fallback_dest = "/etc/pki/ca-trust/source/anchors/kalypso-dev-ca.pem"
                fallback_cmd = ["update-ca-trust"]
            else:
                fallback_dest = "/usr/local/share/ca-certificates/kalypso-dev-ca.crt"
                fallback_cmd = ["update-ca-certificates"]

            tar_data = build_tar({fallback_dest: ca_pem})
            conn = UnixHTTPConnection(self.socket_path, timeout=30)
            conn.request(
                "PUT",
                f"/{DOCKER_API_VERSION}/containers/{svc.container_id}/archive?path={path_param}",
                body=tar_data,
                headers={"Content-Type": "application/x-tar"},
            )
            resp = conn.getresponse()
            resp.read()
            conn.close()

            ok2, _ = self._exec_in_container(svc.container_id, fallback_cmd)
            if ok2:
                logger.info("CA trusted in %s (fallback)", svc.container_name)
            else:
                logger.warning(
                    "Could not update trust store in %s — update-ca-certificates "
                    "and update-ca-trust both failed",
                    svc.container_name,
                )

    def _issue_for_service(self, svc: ManagedService) -> None:
        """Issue a cert and deliver it to a managed service."""
        logger.info(
            "Issuing cert for %s: domains=%s",
            svc.container_name,
            svc.domains,
        )
        try:
            bundle = self.ca.issue(*svc.domains, hours=svc.hours)
        except Exception:
            logger.exception("Failed to issue cert for %s", svc.container_name)
            return

        ca_pem = self.ca.root.cert_pem
        fullchain_path = svc.cert_path.rsplit("/", 1)[0] + "/fullchain.pem"

        files = {
            svc.cert_path: bundle.cert_pem,
            svc.key_path: bundle.key_pem,
            svc.ca_path: ca_pem,
            fullchain_path: bundle.cert_pem + ca_pem,
        }

        if self.auto_inject:
            ok = self._inject_files(svc, files)
            if not ok:
                logger.warning(
                    "Injection failed for %s — container may have read-only filesystem",
                    svc.container_name,
                )
                return
        else:
            logger.info(
                "auto-inject off — cert issued for %s via API only (fingerprint=%s)",
                svc.container_name,
                bundle.cert_fingerprint,
            )

        logger.info(
            "Cert delivered to %s (valid %dh, fingerprint=%s)",
            svc.container_name,
            svc.hours,
            bundle.cert_fingerprint,
        )

        svc.last_issued = time.monotonic()

        # Inject CA into system trust store
        if self.auto_inject and self.auto_trust:
            self._inject_ca_trust(svc, ca_pem)

        # Reload the service
        if self.auto_reload and svc.reload_cmd:
            logger.info("Reloading %s: %s", svc.container_name, svc.reload_cmd)
            ok, _ = self._exec_in_container(svc.container_id, svc.reload_cmd)
            if ok:
                logger.info("Reloaded %s successfully", svc.container_name)

    def discover(self) -> list[ManagedService]:
        """Discover all running containers with kalypso.domains labels."""
        status, containers = self._request(
            "GET",
            '/containers/json?filters={"label":["kalypso.domains"]}',
        )
        if status != 200:
            logger.error("Failed to list containers: %s %s", status, containers)
            return []

        services = []
        for container in containers:
            svc = self._parse_container(container)
            if svc:
                services.append(svc)
                logger.info(
                    "Discovered: %s → %s (cert=%s)",
                    svc.container_name,
                    svc.domains,
                    svc.cert_path,
                )
        return services

    def run_once(self) -> None:
        """Discover and issue certs for all labeled containers (one pass)."""
        services = self.discover()

        with self._lock:
            self._services.clear()
            for svc in services:
                self._services[svc.container_id] = svc

        for svc in services:
            self._issue_for_service(svc)

    def _renewal_loop(self) -> None:
        """Periodically check if certs need renewal."""
        while True:
            time.sleep(60)
            with self._lock:
                for svc in list(self._services.values()):
                    renewal_at = svc.hours * 3600 * 0.5
                    elapsed = time.monotonic() - svc.last_issued
                    if elapsed >= renewal_at:
                        logger.info("Renewing cert for %s", svc.container_name)
                        self._issue_for_service(svc)

    def _event_loop(self) -> None:
        """Watch Docker events for new containers starting."""
        while True:
            try:
                conn = UnixHTTPConnection(self.socket_path, timeout=0)
                filters = json.dumps({"type": ["container"], "event": ["start"]})
                conn.request("GET", f"/{DOCKER_API_VERSION}/events?filters={filters}")
                resp = conn.getresponse()

                buf = b""
                while True:
                    chunk = resp.read(4096)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        if not line.strip():
                            continue
                        try:
                            event = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        container_id = event.get("id", "")
                        attrs = event.get("Actor", {}).get("Attributes", {})
                        if "kalypso.domains" in attrs:
                            logger.info(
                                "Container started with kalypso.domains: %s",
                                attrs.get("name", container_id[:12]),
                            )
                            time.sleep(2)
                            self._on_container_start(container_id)

                conn.close()
            except Exception:
                logger.exception("Event stream error, reconnecting in 5s")
                time.sleep(5)

    def _on_container_start(self, container_id: str) -> None:
        """Handle a new container starting."""
        status, data = self._request("GET", f"/containers/{container_id}/json")
        if status != 200:
            return

        config = data.get("Config", {})
        container_info = {
            "Id": container_id,
            "Names": [data.get("Name", "")],
            "Labels": config.get("Labels", {}),
            "Image": config.get("Image", ""),
        }

        svc = self._parse_container(container_info)
        if not svc:
            return

        with self._lock:
            self._services[container_id] = svc

        self._issue_for_service(svc)

    def run(self) -> None:
        """Main entry point: discover, issue, then watch for changes."""
        logger.info("Docker watcher starting — looking for kalypso.* labels")
        if self.auto_inject:
            logger.info("Auto-inject: ON — certs injected directly into containers")
        else:
            logger.info("Auto-inject: OFF — certs available via API only")
        if self.auto_trust:
            logger.info("Auto-trust: ON — CA injected into container trust stores")
        if self.auto_reload:
            logger.info("Auto-reload: ON — reload commands auto-detected and executed")

        self.run_once()

        renewal_thread = threading.Thread(target=self._renewal_loop, daemon=True)
        renewal_thread.start()

        self._event_loop()
