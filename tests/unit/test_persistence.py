# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import errno
import shutil
import tempfile
import unittest

from module_utils.docker_ansible_summary.persistence import (
    PersistenceError,
    PosixStateStore,
    decode_store_bytes,
)
from module_utils.docker_ansible_summary.transition import (
    new_state_store,
    propose_transition,
)
from module_utils.docker_ansible_summary.validation import (
    canonical_store_bytes,
    normalize_scope,
)


SCOPE = normalize_scope(["fixture-*"])


def observation(identifier, observed_at):
    return {
        "observation_id": identifier,
        "observed_at": observed_at,
        "scope": SCOPE,
        "status": "complete",
        "reason_code": None,
        "warnings": [],
        "discovery_backend": "docker_cli_v1",
        "metadata_gaps": [],
        "containers": {},
    }


def compare_empty(before, after, instance_compatible=True):
    if before is None:
        comparability = "no_baseline"
    elif before["scope"] != after["scope"]:
        comparability = "incompatible_scope"
    else:
        comparability = "exact"
    return {
        "comparability": comparability,
        "comparison_schema_version": 1,
        "from_observation_id": (
            None if before is None else before["observation_id"]
        ),
        "from_observed_at": None if before is None else before["observed_at"],
        "from_scope": None if before is None else before["scope"],
        "to_observation_id": after["observation_id"],
        "to_observed_at": after["observed_at"],
        "to_scope": after["scope"],
        "changes": [],
        "warnings": [],
    }


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.ancestor = tempfile.mkdtemp(
            prefix="docker-ansible-summary-persistence-"
        )
        os.chmod(self.ancestor, 0o700)
        self.state_root = os.path.join(self.ancestor, "state")
        self.backend = PosixStateStore(
            self.state_root,
            "fixture-mdad",
            token_factory=lambda: "a" * 32,
            trusted_root_uid=os.stat("/").st_uid,
        )

    def tearDown(self):
        shutil.rmtree(self.ancestor)

    def candidate(self):
        initial = new_state_store("fixture-mdad")
        return propose_transition(
            initial,
            "pre",
            observation("obs-pre", "2026-07-30T12:00:00Z"),
            scope=SCOPE,
            record_id="record-001",
            comparator=compare_empty,
            release_validation=True,
        )["store"]

    def test_absent_read_does_not_create_namespace(self):
        loaded = self.backend.load(1048576, create_namespace=False)
        self.assertEqual(0, loaded["revision"])
        self.assertFalse(os.path.exists(self.state_root))

    def test_atomic_commit_and_canonical_reload(self):
        candidate = self.candidate()
        committed = self.backend.commit(
            candidate, expected_revision=0, state_max_bytes=1048576
        )
        self.assertEqual(1, committed["revision"])
        state_path = os.path.join(
            self.state_root, "fixture-mdad", "state.json"
        )
        lock_path = os.path.join(
            self.state_root, "fixture-mdad", "state.lock"
        )
        self.assertEqual(0o600, os.stat(state_path).st_mode & 0o777)
        self.assertEqual(0o600, os.stat(lock_path).st_mode & 0o777)
        self.assertEqual(
            candidate,
            self.backend.load(1048576, create_namespace=False),
        )
        with open(state_path, "rb") as stream:
            self.assertEqual(
                canonical_store_bytes(candidate), stream.read()
            )

    def test_revision_conflict_leaves_state_unchanged(self):
        first = self.candidate()
        self.backend.commit(first, 0, 1048576)
        second = self.candidate()
        second["revision"] = 2
        with self.assertRaises(PersistenceError) as raised:
            self.backend.commit(second, 0, 1048576)
        self.assertEqual("revision_conflict", raised.exception.reason)
        self.assertEqual(
            first, self.backend.load(1048576, create_namespace=False)
        )

    def test_noncanonical_and_duplicate_json_are_rejected(self):
        candidate = self.candidate()
        canonical = canonical_store_bytes(candidate)
        with self.assertRaises(PersistenceError) as whitespace:
            decode_store_bytes(
                canonical.replace(b"{", b"{ ", 1),
                "fixture-mdad",
                1048576,
            )
        self.assertEqual("corrupt_state", whitespace.exception.reason)
        with self.assertRaises(PersistenceError) as duplicate:
            decode_store_bytes(
                b'{"schema_version":1,"schema_version":1}\n',
                "fixture-mdad",
                1048576,
            )
        self.assertEqual("corrupt_state", duplicate.exception.reason)
        with self.assertRaises(PersistenceError) as deeply_nested:
            decode_store_bytes(
                b"[" * 2000 + b"]" * 2000 + b"\n",
                "fixture-mdad",
                1048576,
            )
        self.assertEqual(
            "corrupt_state", deeply_nested.exception.reason
        )

    def test_symlinked_state_root_fails_closed(self):
        target = os.path.join(self.ancestor, "target")
        os.mkdir(target, 0o700)
        os.symlink(target, self.state_root)
        with self.assertRaises(PersistenceError) as raised:
            self.backend.load(1048576, create_namespace=True)
        self.assertEqual("unsafe_state_namespace", raised.exception.reason)

    def test_group_writable_nonsticky_ancestor_fails_closed(self):
        os.chmod(self.ancestor, 0o770)
        with self.assertRaises(PersistenceError) as raised:
            self.backend.load(1048576, create_namespace=True)
        self.assertEqual("unsafe_state_namespace", raised.exception.reason)
        self.assertFalse(os.path.exists(self.state_root))

    def test_wrong_role_owned_mode_fails_without_repair(self):
        os.mkdir(self.state_root, 0o755)
        with self.assertRaises(PersistenceError) as raised:
            self.backend.load(1048576, create_namespace=True)
        self.assertEqual("unsafe_state_namespace", raised.exception.reason)
        self.assertEqual(0o755, os.stat(self.state_root).st_mode & 0o777)

    def test_nonregular_state_file_fails_without_blocking(self):
        self.backend.load(1048576, create_namespace=True)
        state_path = os.path.join(
            self.state_root, "fixture-mdad", "state.json"
        )
        os.mkfifo(state_path, 0o600)
        with self.assertRaises(PersistenceError) as raised:
            self.backend.load(1048576, create_namespace=False)
        self.assertEqual("unsafe_state_namespace", raised.exception.reason)
        self.assertTrue(os.path.exists(state_path))

    def test_invalid_existing_lock_is_not_ignored_when_state_is_absent(self):
        os.mkdir(self.state_root, 0o700)
        instance_path = os.path.join(self.state_root, "fixture-mdad")
        os.mkdir(instance_path, 0o700)
        lock_path = os.path.join(instance_path, "state.lock")
        descriptor = os.open(
            lock_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o640
        )
        os.close(descriptor)
        with self.assertRaises(PersistenceError) as raised:
            self.backend.load(1048576, create_namespace=False)
        self.assertEqual("unsafe_state_namespace", raised.exception.reason)
        self.assertEqual(0o640, os.stat(lock_path).st_mode & 0o777)
        self.assertFalse(os.path.exists(os.path.join(instance_path, "state.json")))

    def test_hardlinked_canonical_state_fails_closed(self):
        candidate = self.candidate()
        self.backend.commit(candidate, 0, 1048576)
        state_path = os.path.join(
            self.state_root, "fixture-mdad", "state.json"
        )
        link_path = os.path.join(self.ancestor, "state-hardlink")
        os.link(state_path, link_path)
        with self.assertRaises(PersistenceError) as raised:
            self.backend.load(1048576, create_namespace=False)
        self.assertEqual("unsafe_state_namespace", raised.exception.reason)
        self.assertEqual(2, os.stat(state_path).st_nlink)

    def test_fault_before_replace_keeps_prior_state(self):
        first = self.candidate()
        self.backend.commit(first, 0, 1048576)
        second = propose_transition(
            first,
            "pre",
            observation("obs-second", "2026-07-30T12:00:01Z"),
            scope=SCOPE,
            record_id="record-002",
            comparator=compare_empty,
            release_validation=True,
        )["store"]

        def fail(stage):
            if stage == "before_atomic_replace":
                raise RuntimeError("synthetic")

        faulty = PosixStateStore(
            self.state_root,
            "fixture-mdad",
            token_factory=lambda: "b" * 32,
            fault_injector=fail,
            trusted_root_uid=os.stat("/").st_uid,
        )
        with self.assertRaises(PersistenceError) as raised:
            faulty.commit(second, 1, 1048576)
        self.assertEqual("state_write_failed", raised.exception.reason)
        self.assertFalse(raised.exception.replacement_completed)
        self.assertEqual(
            first, self.backend.load(1048576, create_namespace=False)
        )

    def test_fault_after_replace_reports_indeterminate_durability(self):
        candidate = self.candidate()

        def fail(stage):
            if stage == "after_atomic_replace_before_directory_fsync":
                raise RuntimeError("synthetic")

        faulty = PosixStateStore(
            self.state_root,
            "fixture-mdad",
            token_factory=lambda: "c" * 32,
            fault_injector=fail,
            trusted_root_uid=os.stat("/").st_uid,
        )
        with self.assertRaises(PersistenceError) as raised:
            faulty.commit(candidate, 0, 1048576)
        self.assertEqual("state_write_failed", raised.exception.reason)
        self.assertTrue(raised.exception.replacement_completed)
        self.assertEqual(
            "Retry with the same record_id and unchanged phase inputs",
            raised.exception.replay_guidance,
        )
        self.assertEqual(
            candidate, self.backend.load(1048576, create_namespace=False)
        )

    def test_preexisting_temporary_names_are_ignored(self):
        candidate = self.candidate()
        instance_path = os.path.join(self.state_root, "fixture-mdad")
        self.backend.load(1048576, create_namespace=True)
        target = os.path.join(self.ancestor, "outside")
        with open(target, "wb") as stream:
            stream.write(b"outside")
        hostile = os.path.join(
            instance_path, ".state.json.tmp.attacker-symlink"
        )
        os.symlink(target, hostile)
        self.backend.commit(candidate, 0, 1048576)
        self.assertTrue(os.path.islink(hostile))
        with open(target, "rb") as stream:
            self.assertEqual(b"outside", stream.read())

    def test_lock_timeout_is_bounded_by_injected_monotonic_clock(self):
        class ContendedFcntl(object):
            LOCK_EX = 1
            LOCK_NB = 2
            LOCK_UN = 8

            @staticmethod
            def flock(_descriptor, operation):
                if operation != ContendedFcntl.LOCK_UN:
                    raise OSError(errno.EAGAIN, "contended")

        readings = iter((0, 5))
        backend = PosixStateStore(
            self.state_root,
            "fixture-mdad",
            fcntl_module=ContendedFcntl,
            monotonic=lambda: next(readings),
            sleeper=lambda _seconds: None,
            token_factory=lambda: "d" * 32,
            trusted_root_uid=os.stat("/").st_uid,
        )
        with self.assertRaises(PersistenceError) as raised:
            backend.load(1048576, create_namespace=True)
        self.assertEqual("state_lock_timeout", raised.exception.reason)
        self.assertFalse(
            os.path.exists(
                os.path.join(
                    self.state_root, "fixture-mdad", "state.json"
                )
            )
        )

    def test_oversized_existing_store_fails_before_json_parse(self):
        self.backend.load(1048576, create_namespace=True)
        state_path = os.path.join(
            self.state_root, "fixture-mdad", "state.json"
        )
        descriptor = os.open(
            state_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        try:
            os.write(descriptor, b"x" * 1025)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        with self.assertRaises(PersistenceError) as raised:
            self.backend.load(1024, create_namespace=False)
        self.assertEqual(
            "state_size_limit_exceeded", raised.exception.reason
        )


if __name__ == "__main__":
    unittest.main()
