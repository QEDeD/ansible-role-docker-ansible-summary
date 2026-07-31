# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import absolute_import, division, print_function

import os
import tempfile
import unittest

from module_utils.docker_ansible_summary.engine import (
    OperationFailure,
    execute_operation,
)
from module_utils.docker_ansible_summary.persistence import PosixStateStore


def _scope():
    return {
        "patterns": ["fixture-*"],
        "identity": (
            "sha256:"
            "0f416d928469c6d885f23bebd10cda4eb3c837a5da0229a912c831feff79a207"
        ),
        "comparison_schema_version": 1,
    }


def _observation(identifier, status="complete", reason=None):
    warnings = {
        "docker_unavailable": "Docker daemon was unavailable",
    }
    return {
        "observation_id": identifier,
        "observed_at": "2026-07-30T12:00:00Z",
        "scope": _scope(),
        "status": status,
        "reason_code": reason,
        "warnings": [] if reason is None else [warnings[reason]],
        "discovery_backend": "docker_cli_v1",
        "metadata_gaps": [],
        "containers": {} if status != "unavailable" else None,
    }


def _inputs(state_root, operation, record_id=None):
    value = {
        "enabled": True,
        "operation": operation,
        "instance_id": "fixture",
        "scope": ["fixture-*"],
        "state_root": state_root,
        "record_id": record_id,
    }
    return value


class DiscoverySequence(object):
    def __init__(self, observations):
        self.observations = list(observations)
        self.calls = 0

    def __call__(self, scope, timeout_seconds):
        self.calls += 1
        observation = self.observations.pop(0)
        self._last_scope = scope
        self._last_timeout = timeout_seconds
        return observation


class ForbiddenPersistence(object):
    def __init__(self, *_args, **_kwargs):
        raise AssertionError("store access is forbidden")


def _local_persistence_factory(state_root, instance_id):
    return PosixStateStore(
        state_root,
        instance_id,
        trusted_root_uid=os.stat("/").st_uid,
    )


class EngineTests(unittest.TestCase):
    def test_status_and_check_mode_are_store_free(self):
        status_discovery = DiscoverySequence([_observation("obs-status")])
        status = execute_operation(
            _inputs("/state/is/not/read", "status"),
            discovery=status_discovery,
            persistence_factory=ForbiddenPersistence,
        )
        self.assertEqual("complete", status["observation_status"])
        self.assertIsNone(status["record_id"])
        self.assertFalse(status["simulated"])

        check_discovery = DiscoverySequence([_observation("obs-check")])
        check = execute_operation(
            _inputs("/state/is/not/read", "post", "valid-but-not-looked-up"),
            check_mode=True,
            discovery=check_discovery,
            persistence_factory=ForbiddenPersistence,
        )
        self.assertTrue(check["simulated"])
        self.assertIsNone(check["record_id"])
        self.assertIsNone(check["run_window_delta"])

    def test_pre_post_and_replay_use_one_observation_each(self):
        with tempfile.TemporaryDirectory(prefix="das-engine-") as temporary:
            state_root = os.path.join(temporary, "state")
            discovery = DiscoverySequence(
                [_observation("obs-pre"), _observation("obs-post")]
            )
            pre = execute_operation(
                _inputs(state_root, "pre", "record-1"),
                discovery=discovery,
                persistence_factory=_local_persistence_factory,
            )
            self.assertEqual("committed", pre["persistence_outcome"])
            self.assertEqual("open", pre["journal_status"])
            self.assertFalse(pre["baseline_advanced"])

            post = execute_operation(
                _inputs(state_root, "post", pre["record_id"]),
                discovery=discovery,
                persistence_factory=_local_persistence_factory,
            )
            self.assertEqual("committed", post["persistence_outcome"])
            self.assertEqual("complete", post["journal_status"])
            self.assertTrue(post["baseline_advanced"])
            self.assertEqual("exact", post["run_window_delta"]["comparability"])
            self.assertEqual(2, discovery.calls)

            replay = execute_operation(
                _inputs(state_root, "post", pre["record_id"]),
                discovery=DiscoverySequence([]),
                persistence_factory=_local_persistence_factory,
            )
            self.assertEqual("idempotent", replay["replay_outcome"])
            self.assertEqual("not_attempted", replay["persistence_outcome"])
            self.assertEqual("obs-post", replay["observation"]["observation_id"])

    def test_unavailable_pre_is_committed_as_open_evidence(self):
        with tempfile.TemporaryDirectory(prefix="das-engine-") as temporary:
            result = execute_operation(
                _inputs(os.path.join(temporary, "state"), "pre", "record-2"),
                discovery=DiscoverySequence(
                    [
                        _observation(
                            "obs-unavailable",
                            status="unavailable",
                            reason="docker_unavailable",
                        )
                    ]
                ),
                persistence_factory=_local_persistence_factory,
            )
        self.assertEqual("unavailable", result["observation_status"])
        self.assertEqual("committed", result["persistence_outcome"])
        self.assertEqual("open", result["journal_status"])

    def test_unknown_post_fails_before_discovery_without_namespace_creation(self):
        with tempfile.TemporaryDirectory(prefix="das-engine-") as temporary:
            state_root = os.path.join(temporary, "state")
            discovery = DiscoverySequence([])
            with self.assertRaises(OperationFailure) as captured:
                execute_operation(
                    _inputs(state_root, "post", "unknown-record"),
                    discovery=discovery,
                    persistence_factory=_local_persistence_factory,
                )
            self.assertEqual("unknown_record", captured.exception.reason)
            self.assertEqual("conflict", captured.exception.persistence_outcome)
            self.assertEqual(0, discovery.calls)
            self.assertFalse(os.path.exists(state_root))


if __name__ == "__main__":
    unittest.main()
