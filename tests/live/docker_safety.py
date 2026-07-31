# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared guardrails for every opt-in live-Docker test.

The guard deliberately requires more than a nonempty ``DOCKER_HOST``.  A live
test must target a Unix socket beneath a caller-declared temporary root, and
that root must contain the exact sentinel documented in ``tests/live/README.md``.
This makes accidentally selecting a normal system or rootless user daemon fail
closed before the Docker CLI is invoked.
"""

from __future__ import absolute_import, division, print_function

import os
import shutil
import stat
import tempfile


SENTINEL_BASENAME = ".das-live-disposable-daemon"
SENTINEL_CONTENT = "docker-ansible-summary disposable live daemon v1\n"

_KNOWN_OPERATOR_SOCKET_PATHS = frozenset(
    (
        "/run/docker.sock",
        "/var/run/docker.sock",
        os.path.join(os.path.expanduser("~"), ".docker", "run", "docker.sock"),
    )
)


def _is_nested(path, root):
    try:
        return os.path.commonpath((path, root)) == root and path != root
    except ValueError:
        return False


def require_disposable_docker_host(opt_in_variable):
    """Return ``(docker_path, socket_path, disposable_root)`` or fail closed."""

    if os.environ.get(opt_in_variable) != "1":
        raise AssertionError(
            "set %s=1 only for an isolated disposable daemon"
            % opt_in_variable
        )

    docker_host = os.environ.get("DOCKER_HOST")
    if not docker_host or not docker_host.startswith("unix:///"):
        raise AssertionError(
            "DOCKER_HOST must be an explicit absolute unix:/// socket"
        )
    socket_path = docker_host[len("unix://"):]
    if not os.path.isabs(socket_path):
        raise AssertionError("the disposable Docker socket must be absolute")
    if any(character in socket_path for character in ("?", "#", "\x00")):
        raise AssertionError("the disposable Docker socket path is invalid")

    declared_root = os.environ.get("DAS_LIVE_DOCKER_ROOT")
    if not declared_root or not os.path.isabs(declared_root):
        raise AssertionError(
            "DAS_LIVE_DOCKER_ROOT must name the disposable daemon root"
        )

    root = os.path.realpath(declared_root)
    temporary_root = os.path.realpath(tempfile.gettempdir())
    if root != os.path.abspath(declared_root):
        raise AssertionError("DAS_LIVE_DOCKER_ROOT must not be a symlink")
    if not _is_nested(root, temporary_root):
        raise AssertionError(
            "the disposable daemon root must be below the temporary directory"
        )
    if not _is_nested(os.path.realpath(socket_path), root):
        raise AssertionError(
            "DOCKER_HOST must be nested below DAS_LIVE_DOCKER_ROOT"
        )
    if os.path.realpath(socket_path) in _KNOWN_OPERATOR_SOCKET_PATHS:
        raise AssertionError("refusing a known operator Docker socket")

    sentinel_path = os.path.join(root, SENTINEL_BASENAME)
    sentinel_lstat = os.lstat(sentinel_path)
    if not stat.S_ISREG(sentinel_lstat.st_mode):
        raise AssertionError("the disposable-daemon sentinel must be a file")
    if os.path.islink(sentinel_path):
        raise AssertionError("the disposable-daemon sentinel must not be a link")
    with open(sentinel_path, "r", encoding="ascii") as sentinel:
        if sentinel.read() != SENTINEL_CONTENT:
            raise AssertionError("the disposable-daemon sentinel is invalid")

    socket_lstat = os.lstat(socket_path)
    if not stat.S_ISSOCK(socket_lstat.st_mode):
        raise AssertionError("DOCKER_HOST does not name a Unix socket")

    docker_path = shutil.which("docker")
    if docker_path is None:
        raise AssertionError("Docker CLI is unavailable")
    return docker_path, socket_path, root
