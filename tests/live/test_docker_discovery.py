# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Opt-in smoke test against an explicitly selected disposable Docker daemon."""

from __future__ import absolute_import, division, print_function

import os
import time
import unittest

from module_utils.docker_ansible_summary.discovery import discover
from module_utils.docker_ansible_summary.validation import (
    normalize_scope,
    validate_observation,
)
from tests.live.docker_safety import require_disposable_docker_host


LIVE_ENABLED = os.environ.get("DAS_LIVE_DOCKER") == "1"


@unittest.skipUnless(
    LIVE_ENABLED,
    "set DAS_LIVE_DOCKER=1 with an explicit disposable DOCKER_HOST",
)
class LiveDockerDiscoveryTests(unittest.TestCase):
    def test_discovery_is_complete_bounded_and_canonical(self):
        docker_path, _socket_path, _root = require_disposable_docker_host(
            "DAS_LIVE_DOCKER"
        )
        scope = normalize_scope(
            os.environ.get("DAS_LIVE_SCOPE", "das-live-*")
        )

        started = time.monotonic()
        observation = discover(
            scope,
            timeout_seconds=30,
            docker_path=docker_path,
        )
        elapsed = time.monotonic() - started

        validate_observation(observation, release=True)
        self.assertEqual("complete", observation["status"])
        self.assertIsNone(observation["reason_code"])
        expected_names = {
            value
            for value in os.environ.get(
                "DAS_LIVE_EXPECTED_NAMES", ""
            ).split(",")
            if value
        }
        if expected_names:
            self.assertEqual(
                expected_names, set(observation["containers"])
            )
        self.assertNotIn("stdout", observation)
        self.assertNotIn("stderr", observation)
        print(
            "live discovery: containers=%d elapsed_seconds=%.6f"
            % (len(observation["containers"]), elapsed)
        )


if __name__ == "__main__":
    unittest.main()
