"""Docker auto-discovery — watches for containers with kalypso.* labels.

When a container has a `kalypso.domains` label, Kalypso automatically:
1. Issues a cert for those domains
2. Writes cert files to the shared certs volume
3. Sends a reload signal to the container (auto-detected for nginx/apache/haproxy)
4. Renews before expiry

No sidecar needed. No env vars on your services. Just labels.

Supported labels:
    kalypso.domains     Comma-separated domains (required)
    kalypso.cert_dir    Subdirectory under /certs for this service (default: auto)
    kalypso.hours       Cert lifetime in hours (default: 24)
    kalypso.reload      Reload command (auto-detected for nginx/apache/haproxy)

Uses the Docker Engine API over the Unix socket. No docker-py dependency.
"""

from __future__ import annotations

import http.client
import io
import json
import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from kalypso.ca import CertificateAuthority

logger = logging.getLogger("kalypso.docker")

DEFAULT_CERT_DIR = Path("/certs")
DEFAULT_HOURS = 24
DOCKER_API_VERSION = "v1.41"

# Auto-detect reload commands based on image name
RELOAD_COMMANDS: dict[str, list[str]] = {
    "nginx": ["nginx", "-s", "reload"],
    "httpd": ["apachectl", "graceful"],
    "apache": ["apachectl", "graceful"],
    "haproxy": ["kill", "-USR2", "1"],
    "caddy": ["caddy", "reload", "--config", "/etc/caddy/Caddyfile"],
    "traefik": [],  # Traefik watches files automatically
}


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
    cert_dir: Path
    hours: int
    reload_cmd: list[str] | None
    last_issued: float = 0.0


@dataclass
class DockerWatcher:
    """Watches Docker for containers with kalypso.* labels."""

    ca: CertificateAuthority
    socket_path: str = "/var/run/docker.sock"
    certs_root: Path = DEFAULT_CERT_DIR
    _services: dict[str, ManagedService] = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def _request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        timeout: int = 30,
    ) -> tuple[int, dict | list | str]:
        """Make a request to the Docker Engine API."""
        conn = UnixHTTPConnection(self.socket_path, timeout=timeout)
        headers = {}
        if body:
            headers["Content-Type"] = "application/json"
        conn.request(method, f"/{DOCKER_API_VERSION}{path}", body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode()
        conn.close()
        try:
            return resp.status, json.loads(data)
        except json.JSONDecodeError:
            return resp.status, data

    def _exec_in_container(self, container_id: str, cmd: list[str]) -> bool:
        """Execute a command inside a container via Docker exec API."""
        # Create exec instance
        body = json.dumps({"Cmd": cmd, "AttachStdout": True, "AttachStderr": True}).encode()
        status, data = self._request("POST", f"/containers/{container_id}/exec", body=body)
        if status != 201:
            logger.warning("Failed to create exec in %s: %s", container_id[:12], data)
            return False

        exec_id = data["Id"]

        # Start exec
        start_body = json.dumps({"Detach": False}).encode()
        conn = UnixHTTPConnection(self.socket_path, timeout=30)
        conn.request(
            "POST",
            f"/{DOCKER_API_VERSION}/exec/{exec_id}/start",
            body=start_body,
            headers={"Content-Type": "application/json"},
        )
        resp = conn.getresponse()
        resp.read()
        conn.close()

        # Check exec result
        status, result = self._request("GET", f"/exec/{exec_id}/json")
        if status == 200 and result.get("ExitCode", 1) == 0:
            return True
        logger.warning("Exec in %s exited %s", container_id[:12], result.get("ExitCode"))
        return False

    def _detect_reload_cmd(self, image: str) -> list[str] | None:
        """Auto-detect the reload command from the container image name."""
        image_lower = image.lower().split("/")[-1].split(":")[0]
        for pattern, cmd in RELOAD_COMMANDS.items():
            if pattern in image_lower:
                return cmd if cmd else None
        return None

    def _parse_container(self, container: dict) -> ManagedService | None:
        """Parse a container's labels into a ManagedService."""
        labels = container.get("Labels", {})
        domains_str = labels.get("kalypso.domains", "")
        if not domains_str:
            return None

        domains = [d.strip() for d in domains_str.split(",") if d.strip()]
        if not domains:
            return None

        container_id = container.get("Id", "")
        # Container names from the list API have a leading "/"
        names = container.get("Names", [])
        name = names[0].lstrip("/") if names else container_id[:12]

        # Determine cert output directory
        cert_subdir = labels.get("kalypso.cert_dir", "").strip()
        if cert_subdir:
            cert_dir = self.certs_root / cert_subdir
        else:
            # Default: write directly to certs root (single service)
            # If multiple services, use service name as subdirectory
            cert_dir = self.certs_root

        hours = int(labels.get("kalypso.hours", str(DEFAULT_HOURS)))

        # Reload command: explicit label > auto-detect from image
        reload_label = labels.get("kalypso.reload", "").strip()
        if reload_label:
            reload_cmd = reload_label.split()
        else:
            image = container.get("Image", "")
            reload_cmd = self._detect_reload_cmd(image)

        return ManagedService(
            container_id=container_id,
            container_name=name,
            domains=domains,
            cert_dir=cert_dir,
            hours=hours,
            reload_cmd=reload_cmd,
        )

    def _issue_for_service(self, svc: ManagedService) -> None:
        """Issue a cert and write it for a managed service."""
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

        svc.cert_dir.mkdir(parents=True, exist_ok=True)
        (svc.cert_dir / "cert.pem").write_text(bundle.cert_pem.decode())
        (svc.cert_dir / "key.pem").write_text(bundle.key_pem.decode())
        (svc.cert_dir / "ca.pem").write_text(self.ca.root.cert_pem.decode())
        (svc.cert_dir / "fullchain.pem").write_text(
            bundle.cert_pem.decode() + self.ca.root.cert_pem.decode()
        )

        logger.info(
            "Wrote certs to %s for %s (valid %dh, fingerprint=%s)",
            svc.cert_dir,
            svc.container_name,
            svc.hours,
            bundle.cert_fingerprint,
        )

        svc.last_issued = time.monotonic()

        # Reload the service
        if svc.reload_cmd:
            logger.info("Reloading %s: %s", svc.container_name, svc.reload_cmd)
            ok = self._exec_in_container(svc.container_id, svc.reload_cmd)
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
                    "Discovered: %s → %s",
                    svc.container_name,
                    svc.domains,
                )
        return services

    def _handle_multiple_services(self, services: list[ManagedService]) -> None:
        """If multiple services are found, give each a subdirectory."""
        if len(services) > 1:
            for svc in services:
                if svc.cert_dir == self.certs_root:
                    svc.cert_dir = self.certs_root / svc.container_name

    def run_once(self) -> None:
        """Discover and issue certs for all labeled containers (one pass)."""
        services = self.discover()
        self._handle_multiple_services(services)

        with self._lock:
            self._services.clear()
            for svc in services:
                self._services[svc.container_id] = svc

        for svc in services:
            self._issue_for_service(svc)

    def _renewal_loop(self) -> None:
        """Periodically check if certs need renewal."""
        while True:
            time.sleep(60)  # Check every minute
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

                # Stream events line by line
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
                            # Small delay for container to be fully ready
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

        # Convert inspect format to list format for _parse_container
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
            # If multiple services, use subdirectory
            if self._services and svc.cert_dir == self.certs_root:
                svc.cert_dir = self.certs_root / svc.container_name
            self._services[container_id] = svc

        self._issue_for_service(svc)

    def run(self) -> None:
        """Main entry point: discover, issue, then watch for changes."""
        logger.info("Docker watcher starting — looking for kalypso.* labels")

        # Initial discovery
        self.run_once()

        # Start renewal thread
        renewal_thread = threading.Thread(target=self._renewal_loop, daemon=True)
        renewal_thread.start()

        # Watch for new containers (blocks forever)
        self._event_loop()
