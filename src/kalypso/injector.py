"""Tar archive builder for injecting files into containers via Docker API.

Uses stdlib ``tarfile`` + ``io.BytesIO`` to build in-memory tar archives
that can be PUT to ``/containers/{id}/archive?path=/``.
"""

from __future__ import annotations

import io
import tarfile
import time


def build_tar(files: dict[str, bytes], key_paths: frozenset[str] | None = None) -> bytes:
    """Build an in-memory tar archive from *files*.

    Parameters
    ----------
    files:
        Mapping of absolute paths (inside the container) to file contents.
    key_paths:
        Paths that should get ``0o600`` permissions (private keys).
        Everything else gets ``0o644``.

    Returns
    -------
    bytes
        A gzip-compressed tar archive ready for the Docker archive API.
    """
    if key_paths is None:
        key_paths = frozenset()

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, content in files.items():
            # Normalise to relative path for the tar (Docker wants relative
            # paths when the query param already specifies the root).
            rel = path.lstrip("/")
            info = tarfile.TarInfo(name=rel)
            info.size = len(content)
            info.mtime = int(time.time())
            info.mode = 0o600 if path in key_paths else 0o644
            tar.addfile(info, io.BytesIO(content))

    return buf.getvalue()
