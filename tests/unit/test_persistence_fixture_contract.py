# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Bind the focused persistence fixture to production persistence mechanics.

The planning validator proves that the synthetic oracle is internally
consistent.  These tests independently feed its relevant values into the real
validators, transition engine, and POSIX store, then derive observable results
from those production paths.
"""

from __future__ import absolute_import, division, print_function

import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

import yaml

from module_utils.docker_ansible_summary.engine import (
    OperationFailure,
    execute_operation,
)
from module_utils.docker_ansible_summary.persistence import (
    PersistenceError,
    PosixStateStore,
    decode_store_bytes,
)
from module_utils.docker_ansible_summary.transition import (
    TransitionError,
    apply_retention,
    new_state_store,
    prepare_transition,
    propose_transition,
)
from module_utils.docker_ansible_summary.validation import (
    ValidationError,
    canonical_json_bytes,
    canonical_store_bytes,
    normalize_scope,
    validate_instance_id,
    validate_state_root,
    validate_state_store,
)


FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "conformance"
    / "focused"
    / "persistence.yml"
)
INSTANCE_ID = "fixture-mdad"
SCOPE = normalize_scope(["fixture-*"])
STATE_MAX_BYTES = 16777216


def _load_cases():
    with FIXTURE_PATH.open(encoding="utf-8") as stream:
        document = yaml.safe_load(stream)
    return {case["id"]: case for case in document["cases"]}


def _observation(identifier, observed_at, status="complete"):
    return {
        "observation_id": identifier,
        "observed_at": observed_at,
        "scope": copy.deepcopy(SCOPE),
        "status": status,
        "reason_code": None if status == "complete" else "docker_unavailable",
        "warnings": [],
        "discovery_backend": "docker_cli_v1",
        "metadata_gaps": [],
        "containers": {},
    }


def _backend(state_root, instance_id=INSTANCE_ID, **kwargs):
    kwargs.setdefault("trusted_root_uid", os.stat("/").st_uid)
    return PosixStateStore(state_root, instance_id, **kwargs)


def _write_store_file(backend, store):
    """Seed a valid synthetic revision without bypassing namespace checks."""

    backend.load(STATE_MAX_BYTES, create_namespace=True)
    state_path = os.path.join(
        backend.state_root, backend.instance_id, "state.json"
    )
    descriptor = os.open(
        state_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        encoded = canonical_store_bytes(store)
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return state_path


def _revision_store(revision):
    store = new_state_store(INSTANCE_ID)
    store["revision"] = revision
    validate_state_store(store)
    return store


def _public_inputs(state_root, operation, record_id=None, enabled=True):
    return {
        "enabled": enabled,
        "operation": operation,
        "instance_id": INSTANCE_ID,
        "scope": ["fixture-*"],
        "record_id": record_id,
        "state_root": state_root,
        "report_mode": "none",
    }


class _DiscoveryProbe(object):
    def __init__(self, observations):
        self.observations = list(observations)
        self.calls = 0

    def __call__(self, _scope, _timeout):
        self.calls += 1
        if not self.observations:
            raise AssertionError("unexpected Docker discovery")
        return copy.deepcopy(self.observations.pop(0))


def _set_path(value, dotted_path, replacement):
    parts = dotted_path.split(".")
    cursor = value
    for part in parts[:-1]:
        cursor = cursor[int(part)] if part.isdigit() else cursor[part]
    final = parts[-1]
    if final.isdigit():
        cursor[int(final)] = replacement
    else:
        cursor[final] = replacement


class PersistenceFixtureContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = _load_cases()

    def setUp(self):
        self.ancestor = tempfile.mkdtemp(prefix="das-persistence-binding-")
        os.chmod(self.ancestor, 0o700)

    def tearDown(self):
        try:
            os.chmod(self.ancestor, 0o700)
        except OSError:
            pass
        shutil.rmtree(self.ancestor)

    def state_root(self, suffix="state"):
        return os.path.join(self.ancestor, suffix)

    def test_lexical_state_root_and_instance_grammar(self):
        root_case = self.cases["state_root_lexical_contract"]
        accepted_roots = [
            validate_state_root(value) for value in root_case["accepted"]
        ]
        self.assertEqual(
            root_case["oracle"]["accepted_count"], len(accepted_roots)
        )
        rejected_roots = []
        for item in root_case["rejected"]:
            with self.subTest(root=item["value"]):
                with self.assertRaises(ValidationError) as captured:
                    validate_state_root(item["value"])
                self.assertEqual(item["reason"], captured.exception.code)
                rejected_roots.append(item["value"])
        self.assertEqual(
            root_case["oracle"]["rejected_count"], len(rejected_roots)
        )

        instance_case = self.cases["instance_id_namespace_grammar"]

        def materialize(item):
            if isinstance(item, str):
                return item
            if "value" in item:
                return item["value"]
            recipes = {
                "lowercase_a_followed_by_62_lowercase_b": "a" + ("b" * 62),
                "lowercase_a_followed_by_63_lowercase_b": "a" + ("b" * 63),
            }
            return recipes[item["recipe"]]

        accepted_ids = [
            validate_instance_id(materialize(item))
            for item in instance_case["accepted"]
        ]
        self.assertEqual(
            instance_case["oracle"]["accepted_count"], len(accepted_ids)
        )
        for item in instance_case["rejected"]:
            candidate = materialize(item)
            with self.subTest(instance_id=candidate):
                with self.assertRaises(ValidationError) as captured:
                    validate_instance_id(candidate)
                self.assertEqual(
                    instance_case["oracle"]["rejected_failure_reason"],
                    "invalid_input",
                )
                self.assertEqual(
                    "invalid_instance_id", captured.exception.code
                )
        self.assertEqual(
            instance_case["oracle"]["rejected_count"],
            len(instance_case["rejected"]),
        )

    def test_secure_namespace_and_stable_atomic_replacement(self):
        namespace_case = self.cases["secure_posix_namespace_is_accepted"]
        atomic_case = self.cases["stable_lock_and_atomic_commit_trace"]
        state_root = self.state_root()
        backend = _backend(state_root, token_factory=lambda: "a" * 32)

        prior = _revision_store(
            atomic_case["prior_namespace"]["revision"]
        )
        state_path = _write_store_file(backend, prior)
        instance_path = os.path.dirname(state_path)
        lock_path = os.path.join(instance_path, "state.lock")
        prior_lock = os.stat(lock_path)
        prior_state = os.stat(state_path)

        transition = propose_transition(
            prior,
            "pre",
            _observation("obs-atomic", "2026-07-30T12:00:00Z"),
            scope=SCOPE,
            record_id="record-atomic",
        )
        committed = backend.commit(
            transition["store"],
            expected_revision=prior["revision"],
            state_max_bytes=STATE_MAX_BYTES,
        )
        resulting_lock = os.stat(lock_path)
        resulting_state = os.stat(state_path)

        oracle = atomic_case["oracle"]
        self.assertEqual("committed", oracle["persistence_outcome"])
        self.assertEqual(
            atomic_case["resulting_namespace"]["revision"],
            committed["revision"],
        )
        self.assertEqual(prior_lock.st_ino, resulting_lock.st_ino)
        self.assertTrue(oracle["stable_lock_inode_preserved"])
        self.assertNotEqual(prior_state.st_ino, resulting_state.st_ino)
        self.assertTrue(oracle["state_replaced_as_one_inode"])
        self.assertEqual(
            int(oracle["canonical_state_mode"], 8),
            resulting_state.st_mode & 0o777,
        )
        self.assertEqual(
            oracle["canonical_state_link_count"], resulting_state.st_nlink
        )
        self.assertFalse(
            any(
                name.startswith(".state.json.tmp.")
                for name in os.listdir(instance_path)
            )
        )

        namespace_oracle = namespace_case["oracle"]
        self.assertEqual(
            int(namespace_oracle["state_root_mode"], 8),
            os.stat(state_root).st_mode & 0o777,
        )
        self.assertEqual(
            int(namespace_oracle["instance_directory_mode"], 8),
            os.stat(instance_path).st_mode & 0o777,
        )
        self.assertEqual(
            int(namespace_oracle["regular_file_mode"], 8),
            os.stat(lock_path).st_mode & 0o777,
        )
        self.assertEqual(os.geteuid(), resulting_state.st_uid)
        self.assertTrue(namespace_oracle["owner_is_effective_uid"])

    def test_unsafe_preexisting_namespace_representatives_fail_closed(self):
        case = self.cases["unsafe_preexisting_namespace_fails_closed"]
        expected_variants = {
            variant["id"] for variant in case["variants"]
        }
        exercised = set()

        def assert_unsafe(state_root, setup=None, backend_factory=_backend):
            if setup is not None:
                setup()
            candidate_backend = backend_factory(state_root)
            with self.assertRaises(PersistenceError) as captured:
                candidate_backend.load(
                    STATE_MAX_BYTES, create_namespace=True
                )
            self.assertEqual(
                case["oracle"]["failure_reason_for_each"],
                captured.exception.reason,
            )

        real = os.path.join(self.ancestor, "real")
        os.mkdir(real, 0o700)
        linked = os.path.join(self.ancestor, "linked")
        os.symlink(real, linked)
        assert_unsafe(os.path.join(linked, "state"))
        exercised.add("symlinked_ancestor")

        assert_unsafe(
            os.path.join(self.ancestor, "missing", "state")
        )
        exercised.add("missing_ancestor")

        writable_parent = os.path.join(self.ancestor, "writable")
        os.mkdir(writable_parent, 0o777)
        assert_unsafe(os.path.join(writable_parent, "state"))
        exercised.add("world_writable_nonsticky_ancestor")

        symlink_target = os.path.join(self.ancestor, "state-target")
        os.mkdir(symlink_target, 0o700)
        symlink_root = self.state_root("state-link")
        os.symlink(symlink_target, symlink_root)
        assert_unsafe(symlink_root)
        exercised.add("symlinked_state_root")

        wrong_mode_root = self.state_root("wrong-mode-root")
        os.mkdir(wrong_mode_root, 0o750)
        before_mode = os.stat(wrong_mode_root).st_mode & 0o777
        assert_unsafe(wrong_mode_root)
        self.assertEqual(
            before_mode, os.stat(wrong_mode_root).st_mode & 0o777
        )
        exercised.add("group_readable_state_root")

        wrong_owner_root = self.state_root("wrong-owner-root")
        os.mkdir(wrong_owner_root, 0o700)

        def wrong_owner_backend(path):
            return PosixStateStore(
                path,
                INSTANCE_ID,
                effective_uid=os.geteuid() + 1,
                trusted_root_uid=os.geteuid(),
            )

        assert_unsafe(
            wrong_owner_root, backend_factory=wrong_owner_backend
        )
        exercised.add("wrong_state_root_owner")

        class ProjectedOwnerOs(object):
            """Project one descriptor as foreign-owned without chown."""

            def __init__(self, target):
                self.target = os.path.realpath(target)

            def __getattr__(self, name):
                return getattr(os, name)

            def fstat(self, descriptor):
                result = os.fstat(descriptor)
                descriptor_path = os.path.realpath(
                    "/proc/self/fd/{0}".format(descriptor)
                )
                if descriptor_path == self.target:
                    fields = list(result)
                    fields[4] = os.geteuid() + 100
                    return os.stat_result(fields)
                return result

        foreign_ancestor_root = self.state_root("foreign-ancestor-state")

        def foreign_ancestor_backend(path):
            return PosixStateStore(
                path,
                INSTANCE_ID,
                os_module=ProjectedOwnerOs(self.ancestor),
                trusted_root_uid=os.stat("/").st_uid,
            )

        assert_unsafe(
            foreign_ancestor_root,
            backend_factory=foreign_ancestor_backend,
        )
        exercised.add("untrusted_ancestor_owner")

        wrong_instance_type_root = self.state_root("instance-type")
        os.mkdir(wrong_instance_type_root, 0o700)
        with open(
            os.path.join(wrong_instance_type_root, INSTANCE_ID), "wb"
        ):
            pass
        assert_unsafe(wrong_instance_type_root)
        exercised.add("wrong_instance_directory_type")

        wrong_instance_mode_root = self.state_root("instance-mode")
        os.mkdir(wrong_instance_mode_root, 0o700)
        wrong_instance = os.path.join(
            wrong_instance_mode_root, INSTANCE_ID
        )
        os.mkdir(wrong_instance, 0o750)
        assert_unsafe(wrong_instance_mode_root)
        self.assertEqual(0o750, os.stat(wrong_instance).st_mode & 0o777)
        exercised.add("wrong_instance_directory_mode")

        foreign_instance_root = self.state_root("foreign-instance")
        normal_instance_backend = _backend(foreign_instance_root)
        normal_instance_backend.load(
            STATE_MAX_BYTES, create_namespace=True
        )
        foreign_instance_path = os.path.join(
            foreign_instance_root, INSTANCE_ID
        )

        def foreign_instance_backend(path):
            return PosixStateStore(
                path,
                INSTANCE_ID,
                os_module=ProjectedOwnerOs(foreign_instance_path),
                trusted_root_uid=os.stat("/").st_uid,
            )

        assert_unsafe(
            foreign_instance_root,
            backend_factory=foreign_instance_backend,
        )
        exercised.add("wrong_instance_directory_owner")

        for variant_id, kind in (
            ("symlinked_canonical_state", "symlink"),
            ("wrong_canonical_state_mode", "wrong_mode"),
            ("hardlinked_canonical_state", "hardlink"),
        ):
            state_root = self.state_root("canonical-" + kind)
            backend = _backend(state_root)
            backend.load(STATE_MAX_BYTES, create_namespace=True)
            state_path = os.path.join(
                state_root, INSTANCE_ID, "state.json"
            )
            if kind == "symlink":
                target = os.path.join(self.ancestor, "outside-state")
                with open(target, "wb") as stream:
                    stream.write(b"outside")
                os.symlink(target, state_path)
            else:
                descriptor = os.open(
                    state_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600 if kind == "hardlink" else 0o640,
                )
                os.close(descriptor)
                if kind == "hardlink":
                    os.link(
                        state_path,
                        os.path.join(self.ancestor, "state-hardlink"),
                    )
            assert_unsafe(state_root)
            exercised.add(variant_id)

        foreign_state_root = self.state_root("foreign-state")
        normal_state_backend = _backend(foreign_state_root)
        foreign_state_path = _write_store_file(
            normal_state_backend, _revision_store(1)
        )

        def foreign_state_backend(path):
            return PosixStateStore(
                path,
                INSTANCE_ID,
                os_module=ProjectedOwnerOs(foreign_state_path),
                trusted_root_uid=os.stat("/").st_uid,
            )

        assert_unsafe(
            foreign_state_root, backend_factory=foreign_state_backend
        )
        exercised.add("wrong_canonical_state_owner")

        for variant_id, kind in (
            ("lock_is_directory", "directory"),
            ("wrong_lock_mode", "wrong_mode"),
        ):
            state_root = self.state_root("lock-" + kind)
            os.mkdir(state_root, 0o700)
            instance_path = os.path.join(state_root, INSTANCE_ID)
            os.mkdir(instance_path, 0o700)
            lock_path = os.path.join(instance_path, "state.lock")
            if kind == "directory":
                os.mkdir(lock_path, 0o700)
            else:
                descriptor = os.open(
                    lock_path,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL,
                    0o640,
                )
                os.close(descriptor)
            assert_unsafe(state_root)
            exercised.add(variant_id)

        class InodeMismatchStore(PosixStateStore):
            def _stat_name(self, directory_fd, name):
                result = PosixStateStore._stat_name(
                    self, directory_fd, name
                )
                if name == "state.lock":
                    fields = list(result)
                    fields[1] += 1
                    return os.stat_result(fields)
                return result

        mismatch_root = self.state_root("inode-mismatch")

        def mismatch_backend(path):
            return InodeMismatchStore(
                path,
                INSTANCE_ID,
                trusted_root_uid=os.stat("/").st_uid,
            )

        assert_unsafe(mismatch_root, backend_factory=mismatch_backend)
        exercised.add("name_descriptor_inode_mismatch")

        self.assertEqual(expected_variants, exercised)
        self.assertEqual(
            case["oracle"]["variant_count"], len(expected_variants)
        )

    def test_absent_namespace_creation_is_operation_bounded(self):
        case = self.cases[
            "absent_namespace_creation_is_operation_bounded"
        ]
        by_key = {}
        for variant in case["variants"]:
            invocation = variant["invocation"]
            key = (
                invocation.get("enabled", True),
                invocation.get("operation"),
                invocation.get("check_mode", False),
                invocation.get("record_id", "__omitted__"),
            )
            by_key[key] = variant

        status_root = self.state_root("status")
        status_discovery = _DiscoveryProbe(
            [_observation("obs-status", "2026-07-30T12:00:00Z")]
        )
        status_result = execute_operation(
            _public_inputs(status_root, "status"),
            discovery=status_discovery,
        )
        status_oracle = by_key[(True, "status", False, "__omitted__")]
        self.assertEqual(
            status_oracle["persistence_outcome"],
            status_result["persistence_outcome"],
        )
        self.assertFalse(os.path.exists(status_root))

        check_root = self.state_root("check")
        check_result = execute_operation(
            _public_inputs(check_root, "pre"),
            check_mode=True,
            discovery=_DiscoveryProbe(
                [_observation("obs-check", "2026-07-30T12:00:00Z")]
            ),
        )
        check_oracle = by_key[(True, "pre", True, "__omitted__")]
        self.assertEqual(
            check_oracle["persistence_outcome"],
            check_result["persistence_outcome"],
        )
        self.assertFalse(os.path.exists(check_root))

        disabled_root = self.state_root("disabled")
        disabled_discovery = _DiscoveryProbe([])
        disabled_result = execute_operation(
            _public_inputs(
                disabled_root, "pre", enabled=False
            ),
            discovery=disabled_discovery,
        )
        self.assertEqual(0, disabled_discovery.calls)
        self.assertEqual(
            by_key[(False, None, False, "__omitted__")][
                "persistence_outcome"
            ],
            disabled_result["persistence_outcome"],
        )
        self.assertFalse(os.path.exists(disabled_root))

        unknown_root = self.state_root("unknown-post")
        unknown_discovery = _DiscoveryProbe([])
        unknown_id = "caller-unknown-in-absent-store"
        with self.assertRaises(OperationFailure) as captured:
            execute_operation(
                _public_inputs(
                    unknown_root, "post", record_id=unknown_id
                ),
                discovery=unknown_discovery,
                persistence_factory=_backend,
            )
        unknown_oracle = by_key[(True, "post", False, unknown_id)]
        self.assertEqual(
            unknown_oracle["failure_reason"], captured.exception.reason
        )
        self.assertEqual(
            unknown_oracle["persistence_outcome"],
            captured.exception.persistence_outcome,
        )
        self.assertEqual(0, unknown_discovery.calls)
        self.assertFalse(os.path.exists(unknown_root))

        for operation, suffix in (("pre", "pre"), ("post", "post")):
            state_root = self.state_root(suffix)
            result = execute_operation(
                _public_inputs(state_root, operation),
                discovery=_DiscoveryProbe(
                    [
                        _observation(
                            "obs-" + suffix,
                            "2026-07-30T12:00:00Z",
                        )
                    ]
                ),
                persistence_factory=_backend,
                record_id_factory=lambda: "record-" + suffix,
            )
            variant = by_key[
                (True, operation, False, None if operation == "post" else "__omitted__")
            ]
            self.assertEqual(
                variant["persistence_outcome"],
                result["persistence_outcome"],
            )
            self.assertTrue(os.path.exists(state_root))
            self.assertEqual(
                int(case["oracle"]["new_directory_mode"], 8),
                os.stat(state_root).st_mode & 0o777,
            )
            self.assertEqual(
                int(case["oracle"]["new_file_mode"], 8),
                os.stat(
                    os.path.join(
                        state_root, INSTANCE_ID, "state.json"
                    )
                ).st_mode
                & 0o777,
            )

    def test_preexisting_temporary_names_remain_untouched(self):
        case = self.cases[
            "preexisting_temporary_names_are_ignored"
        ]
        state_root = self.state_root()
        backend = _backend(state_root, token_factory=lambda: "b" * 32)
        prior = _revision_store(
            case["canonical_state"]["revision"]
        )
        _write_store_file(backend, prior)
        instance_path = os.path.join(state_root, INSTANCE_ID)

        outside_symlink = os.path.join(self.ancestor, "outside-symlink")
        outside_hardlink = os.path.join(self.ancestor, "outside-hardlink")
        with open(outside_symlink, "wb") as stream:
            stream.write(b"symlink-target")
        with open(outside_hardlink, "wb") as stream:
            stream.write(b"hardlink-target")
        hostile_symlink = os.path.join(
            instance_path, case["preexisting_names"][0]["name"]
        )
        hostile_hardlink = os.path.join(
            instance_path, case["preexisting_names"][1]["name"]
        )
        os.symlink(outside_symlink, hostile_symlink)
        os.link(outside_hardlink, hostile_hardlink)
        before_hardlink = os.stat(hostile_hardlink)

        transition = propose_transition(
            prior,
            "pre",
            _observation("obs-temp", "2026-07-30T12:00:00Z"),
            scope=SCOPE,
            record_id="record-temp",
        )
        backend.commit(
            transition["store"],
            prior["revision"],
            STATE_MAX_BYTES,
        )

        oracle = case["oracle"]
        self.assertTrue(os.path.islink(hostile_symlink))
        self.assertEqual(
            os.stat(hostile_hardlink).st_ino, before_hardlink.st_ino
        )
        self.assertTrue(oracle["preexisting_names_opened"] is False)
        self.assertTrue(oracle["preexisting_names_unlinked"] is False)
        with open(outside_symlink, "rb") as stream:
            self.assertEqual(b"symlink-target", stream.read())
        with open(outside_hardlink, "rb") as stream:
            self.assertEqual(b"hardlink-target", stream.read())

    def test_atomic_fault_boundaries_match_visible_store_contract(self):
        before_case = self.cases["fault_before_atomic_replace"]
        after_case = self.cases[
            "fault_after_replace_before_directory_fsync"
        ]

        for case, stage in (
            (before_case, "before_atomic_replace"),
            (
                after_case,
                "after_atomic_replace_before_directory_fsync",
            ),
        ):
            with self.subTest(stage=stage):
                state_root = self.state_root(stage)
                normal = _backend(state_root)
                prior = _revision_store(case["prior_state"]["revision"])
                state_path = _write_store_file(normal, prior)
                with open(state_path, "rb") as stream:
                    prior_bytes = stream.read()
                transition = propose_transition(
                    prior,
                    "pre",
                    _observation(
                        "obs-" + stage,
                        "2026-07-30T12:00:00Z",
                    ),
                    scope=SCOPE,
                    record_id=(
                        case.get("candidate_state", {}).get("record_id")
                        or "record-before-fault"
                    ),
                )

                def inject(observed_stage):
                    if observed_stage == stage:
                        raise RuntimeError("synthetic")

                faulty = _backend(
                    state_root,
                    token_factory=lambda: "c" * 32,
                    fault_injector=inject,
                )
                with self.assertRaises(PersistenceError) as captured:
                    faulty.commit(
                        transition["store"],
                        prior["revision"],
                        STATE_MAX_BYTES,
                    )
                self.assertEqual(
                    case["oracle"]["failure_reason"],
                    captured.exception.reason,
                )
                visible = normal.load(
                    STATE_MAX_BYTES, create_namespace=False
                )
                if stage == "before_atomic_replace":
                    self.assertFalse(
                        captured.exception.replacement_completed
                    )
                    self.assertEqual(
                        case["oracle"]["revision_after"],
                        visible["revision"],
                    )
                    with open(state_path, "rb") as stream:
                        self.assertEqual(prior_bytes, stream.read())
                else:
                    self.assertTrue(
                        captured.exception.replacement_completed
                    )
                    self.assertEqual(
                        case["candidate_state"]["revision"],
                        visible["revision"],
                    )
                    self.assertEqual(
                        case["oracle"]["failure_task_result"][
                            "docker_ansible_summary_failure"
                        ]["replay_guidance"],
                        captured.exception.replay_guidance,
                    )
                    self.assertEqual(
                        case["oracle"][
                            "visible_state_immediately_after_replace"
                        ],
                        "candidate",
                    )

    def test_lost_ack_and_delayed_phase_replays_are_idempotent(self):
        lost_pre = self.cases["lost_ack_replay_with_caller_id"]
        initial = _revision_store(lost_pre["prior_state"]["revision"])
        pre_observation = _observation(
            "obs-caller-known-003", "2026-07-30T12:00:00Z"
        )
        first = propose_transition(
            initial,
            "pre",
            pre_observation,
            scope=SCOPE,
            record_id=lost_pre["first_invocation"]["record_id"],
        )
        replay = prepare_transition(
            first["store"],
            "pre",
            SCOPE,
            record_id=lost_pre["identical_retry"]["record_id"],
        )
        self.assertEqual(
            lost_pre["oracle"]["replay_outcome"],
            replay["replay_outcome"],
        )
        self.assertEqual(
            lost_pre["oracle"]["persistence_outcome"],
            replay["persistence_outcome"],
        )
        self.assertEqual(
            lost_pre["oracle"]["revision_after_retry"],
            replay["store"]["revision"],
        )
        self.assertEqual(
            lost_pre["oracle"]["duplicate_records"],
            len(replay["store"]["journal"]) - 1,
        )
        self.assertEqual(
            lost_pre["oracle"]["durable_record_status"],
            replay["record"]["status"],
        )

        delayed = self.cases["delayed_pre_replay_after_completed_post"]
        delayed_initial = _revision_store(
            delayed["prior_state"]["revision"] - 2
        )
        delayed_pre = propose_transition(
            delayed_initial,
            "pre",
            _observation(
                delayed["oracle"]["returned_phase_observation_id"],
                "2026-07-30T12:00:00Z",
            ),
            scope=SCOPE,
            record_id=delayed["invocation"]["record_id"],
        )
        completed = propose_transition(
            delayed_pre["store"],
            "post",
            _observation(
                delayed["prior_state"]["latest_complete_post_id"],
                "2026-07-30T12:00:01Z",
            ),
            scope=SCOPE,
            record_id=delayed["invocation"]["record_id"],
        )
        delayed_replay = prepare_transition(
            completed["store"],
            "pre",
            SCOPE,
            record_id=delayed["invocation"]["record_id"],
        )
        delayed_oracle = delayed["oracle"]
        self.assertEqual(
            delayed_oracle["revision_after"],
            delayed_replay["store"]["revision"],
        )
        self.assertEqual(
            delayed_oracle["returned_phase_observation_id"],
            delayed_replay["observation"]["observation_id"],
        )
        self.assertEqual(
            delayed_oracle["returned_phase_baseline_advanced"],
            delayed_replay["baseline_advanced"],
        )
        self.assertEqual(
            delayed_oracle["machine_result_journal_status"],
            delayed_replay["journal_status"],
        )
        self.assertEqual(
            delayed_oracle["latest_complete_post_id"],
            completed["store"]["latest_complete_post"]["observation_id"],
        )

        lost_post = self.cases["lost_ack_replay_of_committed_post"]
        lost_post_initial = _revision_store(
            lost_post["prior_state"]["revision"] - 2
        )
        lost_post_pre = propose_transition(
            lost_post_initial,
            "pre",
            _observation(
                "obs-caller-known-post-pre",
                "2026-07-30T12:00:00Z",
            ),
            scope=SCOPE,
            record_id=lost_post["identical_retry"]["record_id"],
        )
        lost_post_committed = propose_transition(
            lost_post_pre["store"],
            "post",
            _observation(
                lost_post["prior_state"]["latest_complete_post_id"],
                "2026-07-30T12:00:01Z",
            ),
            scope=SCOPE,
            record_id=lost_post["identical_retry"]["record_id"],
        )
        post_replay = prepare_transition(
            lost_post_committed["store"],
            "post",
            SCOPE,
            record_id=lost_post["identical_retry"]["record_id"],
        )
        post_oracle = lost_post["oracle"]
        self.assertEqual(
            post_oracle["replay_outcome"],
            post_replay["replay_outcome"],
        )
        self.assertEqual(
            post_oracle["revision_after_retry"],
            post_replay["store"]["revision"],
        )
        self.assertEqual(
            post_oracle["returned_result"]["observation_id"],
            post_replay["observation"]["observation_id"],
        )
        self.assertEqual(
            post_oracle["returned_result"]["baseline_advanced"],
            post_replay["baseline_advanced"],
        )
        self.assertEqual(
            post_oracle["returned_result"]["journal_status"],
            post_replay["journal_status"],
        )

    def test_retained_delta_keeps_endpoint_context_after_source_pruning(self):
        case = self.cases[
            "retained_delta_preserves_endpoint_context"
        ]
        store = new_state_store(INSTANCE_ID)
        old_baseline = _observation(
            case["retained_record"]["between_observation_delta"][
                "from_observation_id"
            ],
            case["retained_record"]["between_observation_delta"][
                "from_observed_at"
            ],
        )
        store = propose_transition(
            store,
            "post",
            old_baseline,
            scope=SCOPE,
            record_id=None,
            record_id_factory=lambda: "old-baseline-record",
        )["store"]
        retained_pre = _observation(
            case["retained_record"]["between_observation_delta"][
                "to_observation_id"
            ],
            case["retained_record"]["between_observation_delta"][
                "to_observed_at"
            ],
        )
        store = propose_transition(
            store,
            "pre",
            retained_pre,
            scope=SCOPE,
            record_id=case["retained_record"]["record_id"],
        )["store"]
        store = propose_transition(
            store,
            "post",
            _observation(
                case["surrounding_state"]["latest_complete_post_id"],
                "2026-02-05T08:00:00Z",
            ),
            scope=SCOPE,
            record_id=None,
            record_id_factory=lambda: "newer-baseline-record",
            journal_max_records=2,
        )["store"]

        retained = next(
            record
            for record in store["journal"]
            if record["record_id"]
            == case["retained_record"]["record_id"]
        )
        delta = retained["between_observation_delta"]
        oracle = case["oracle"]
        self.assertNotIn(
            "old-baseline-record",
            [record["record_id"] for record in store["journal"]],
        )
        self.assertTrue(oracle["delta_self_contained"])
        self.assertEqual(
            case["retained_record"]["between_observation_delta"][
                "from_observation_id"
            ],
            delta["from_observation_id"],
        )
        self.assertEqual(
            case["retained_record"]["between_observation_delta"][
                "from_observed_at"
            ],
            delta["from_observed_at"],
        )
        self.assertEqual(
            case["retained_record"]["between_observation_delta"][
                "from_scope"
            ],
            delta["from_scope"],
        )

    def test_identity_conflicts_are_pre_discovery_and_nonmutating(self):
        signature_case = self.cases[
            "retained_record_signature_conflict"
        ]
        store = _revision_store(
            signature_case["prior_state"]["revision"] - 1
        )
        store = propose_transition(
            store,
            "pre",
            _observation("obs-signature", "2026-07-30T12:00:00Z"),
            scope=SCOPE,
            record_id=signature_case["invocation"]["record_id"],
        )["store"]
        durable = canonical_store_bytes(store)
        with self.assertRaises(TransitionError) as captured:
            prepare_transition(
                store,
                "pre",
                SCOPE,
                record_id=signature_case["invocation"]["record_id"],
                correlation_id="changes-the-phase-signature",
            )
        self.assertEqual(
            signature_case["oracle"]["conflict_reason"],
            captured.exception.reason,
        )
        self.assertEqual(durable, canonical_store_bytes(store))

        for case_id in (
            "recently_pruned_record_conflict",
            "never_known_record",
        ):
            case = self.cases[case_id]
            prior = _revision_store(case["prior_state"]["revision"])
            prior["recently_pruned_record_ids"] = list(
                case["prior_state"]["recently_pruned_record_ids"]
            )
            validate_state_store(prior)
            durable = canonical_store_bytes(prior)
            with self.subTest(case=case_id):
                with self.assertRaises(TransitionError) as conflict:
                    prepare_transition(
                        prior,
                        case["invocation"]["operation"],
                        SCOPE,
                        record_id=case["invocation"]["record_id"],
                    )
                self.assertEqual(
                    case["oracle"]["conflict_reason"],
                    conflict.exception.reason,
                )
                self.assertEqual(durable, canonical_store_bytes(prior))

    def test_commit_time_prune_and_same_phase_races(self):
        pruned_case = self.cases["record_pruned_during_discovery"]
        loaded = _revision_store(
            pruned_case["loaded_state"]["revision"] - 1
        )
        loaded = propose_transition(
            loaded,
            "pre",
            _observation("obs-racing-pre", "2026-07-30T12:00:00Z"),
            scope=SCOPE,
            record_id=pruned_case["loaded_state"]["journal"][0][
                "record_id"
            ],
        )["store"]
        prepared = prepare_transition(
            loaded,
            "post",
            SCOPE,
            record_id=pruned_case["loaded_state"]["journal"][0][
                "record_id"
            ],
        )
        concurrent = copy.deepcopy(loaded)
        concurrent["revision"] += 1
        concurrent["journal"] = []
        concurrent["recently_pruned_record_ids"] = list(
            pruned_case["concurrent_committed_state"][
                "recently_pruned_record_ids"
            ]
        )
        validate_state_store(concurrent)
        durable = canonical_store_bytes(concurrent)
        with self.assertRaises(TransitionError) as captured:
            propose_transition(
                concurrent,
                "post",
                _observation(
                    pruned_case["proposed_transition"]["observation_id"],
                    "2026-07-30T12:00:01Z",
                ),
                scope=SCOPE,
                record_id=pruned_case["loaded_state"]["journal"][0][
                    "record_id"
                ],
                expected_revision=prepared["expected_revision"],
                phase_signature_value=prepared["phase_signature"],
                prepared=prepared,
            )
        self.assertEqual(
            pruned_case["oracle"]["conflict_reason"],
            captured.exception.reason,
        )
        self.assertEqual(durable, canonical_store_bytes(concurrent))

        post_case = self.cases[
            "concurrent_same_phase_commit_becomes_idempotent_replay"
        ]
        loaded_post = _revision_store(
            post_case["loaded_state"]["revision"] - 1
        )
        loaded_post = propose_transition(
            loaded_post,
            "pre",
            _observation(
                "obs-racing-same-phase-pre",
                "2026-07-30T12:00:00Z",
            ),
            scope=SCOPE,
            record_id=post_case["invocation"]["record_id"],
        )["store"]
        prepared_post = prepare_transition(
            loaded_post,
            "post",
            SCOPE,
            record_id=post_case["invocation"]["record_id"],
        )
        committed_post = propose_transition(
            loaded_post,
            "post",
            _observation(
                post_case["concurrent_committed_state"]["journal"][0][
                    "post_observation_id"
                ],
                "2026-07-30T12:00:01Z",
            ),
            scope=SCOPE,
            record_id=post_case["invocation"]["record_id"],
            prepared=prepared_post,
        )["store"]
        replay_post = propose_transition(
            committed_post,
            "post",
            _observation(
                post_case["proposed_transition"]["observation_id"],
                "2026-07-30T12:00:02Z",
            ),
            scope=SCOPE,
            record_id=post_case["invocation"]["record_id"],
            expected_revision=prepared_post["expected_revision"],
            phase_signature_value=prepared_post["phase_signature"],
            prepared=prepared_post,
        )
        post_oracle = post_case["oracle"]
        self.assertEqual(
            post_oracle["replay_outcome"],
            replay_post["replay_outcome"],
        )
        self.assertEqual(
            post_oracle["revision_after"],
            replay_post["store"]["revision"],
        )
        self.assertEqual(
            post_oracle["returned_observation_id"],
            replay_post["observation"]["observation_id"],
        )
        self.assertEqual(
            post_oracle["returned_baseline_advanced"],
            replay_post["baseline_advanced"],
        )

        pre_case = self.cases[
            "concurrent_pre_commit_becomes_idempotent_replay"
        ]
        loaded_pre = _revision_store(pre_case["loaded_state"]["revision"])
        prepared_pre = prepare_transition(
            loaded_pre,
            "pre",
            SCOPE,
            record_id=pre_case["invocation"]["record_id"],
        )
        committed_pre = propose_transition(
            loaded_pre,
            "pre",
            _observation(
                pre_case["concurrent_committed_state"]["journal"][0][
                    "pre_observation_id"
                ],
                "2026-07-30T12:00:00Z",
            ),
            scope=SCOPE,
            record_id=pre_case["invocation"]["record_id"],
            prepared=prepared_pre,
        )["store"]
        replay_pre = propose_transition(
            committed_pre,
            "pre",
            _observation(
                pre_case["proposed_transition"]["observation_id"],
                "2026-07-30T12:00:01Z",
            ),
            scope=SCOPE,
            record_id=pre_case["invocation"]["record_id"],
            expected_revision=prepared_pre["expected_revision"],
            phase_signature_value=prepared_pre["phase_signature"],
            prepared=prepared_pre,
        )
        pre_oracle = pre_case["oracle"]
        self.assertEqual(
            pre_oracle["replay_outcome"],
            replay_pre["replay_outcome"],
        )
        self.assertEqual(
            pre_oracle["revision_after"],
            replay_pre["store"]["revision"],
        )
        self.assertEqual(
            pre_oracle["returned_observation_id"],
            replay_pre["observation"]["observation_id"],
        )
        self.assertEqual(
            pre_oracle["returned_expected_post_revision"],
            replay_pre["record"]["expected_post_revision"],
        )

    def test_count_and_recent_id_retention_use_fixture_order(self):
        prune_case = self.cases["retention_prunes_oldest_open_record"]
        store = new_state_store(INSTANCE_ID)
        store = propose_transition(
            store,
            "pre",
            _observation(
                "obs-old-open",
                prune_case["prior_state"]["journal"][0]["created_at"],
            ),
            scope=SCOPE,
            record_id=prune_case["prior_state"]["journal"][0]["record_id"],
        )["store"]
        store = propose_transition(
            store,
            "post",
            _observation(
                "obs-newer-complete",
                prune_case["prior_state"]["journal"][1]["created_at"],
            ),
            scope=SCOPE,
            record_id=None,
            record_id_factory=lambda: (
                prune_case["prior_state"]["journal"][1]["record_id"]
            ),
        )["store"]
        newest = propose_transition(
            store,
            "post",
            _observation(
                prune_case["oracle"]["latest_complete_post_id"],
                prune_case["transaction"]["append_record"]["created_at"],
            ),
            scope=SCOPE,
            record_id=None,
            record_id_factory=lambda: (
                prune_case["transaction"]["append_record"]["record_id"]
            ),
            journal_max_records=prune_case["transaction"][
                "journal_max_records"
            ],
        )
        prune_oracle = prune_case["oracle"]
        self.assertEqual(
            prune_oracle["retained_record_ids"],
            [
                record["record_id"]
                for record in newest["store"]["journal"]
            ],
        )
        self.assertEqual(
            prune_oracle["pruned_record_ids"],
            newest["pruned_record_ids"],
        )
        self.assertEqual(
            prune_oracle["recently_pruned_record_ids_after"],
            newest["store"]["recently_pruned_record_ids"],
        )
        self.assertEqual(
            prune_oracle["latest_complete_post_id"],
            newest["store"]["latest_complete_post"]["observation_id"],
        )
        self.assertNotIn(
            "incomplete",
            [record["status"] for record in newest["store"]["journal"]],
        )

        recent_case = self.cases["recent_id_cap_evicts_oldest"]
        prior = new_state_store(INSTANCE_ID)
        for record, observation_id in zip(
            recent_case["prior_state"]["journal"],
            ("obs-about-to-prune", "obs-retained"),
        ):
            prior = propose_transition(
                prior,
                "post",
                _observation(observation_id, record["created_at"]),
                scope=SCOPE,
                record_id=None,
                record_id_factory=lambda record_id=record["record_id"]: (
                    record_id
                ),
            )["store"]
        prior["recently_pruned_record_ids"] = list(
            recent_case["prior_state"]["recently_pruned_record_ids"]
        )
        validate_state_store(prior)
        recent = propose_transition(
            prior,
            "post",
            _observation(
                "obs-newest",
                recent_case["transaction"]["append_record"]["created_at"],
            ),
            scope=SCOPE,
            record_id=None,
            record_id_factory=lambda: (
                recent_case["transaction"]["append_record"]["record_id"]
            ),
            journal_max_records=recent_case["oracle"][
                "effective_recent_id_cap"
            ],
        )
        recent_oracle = recent_case["oracle"]
        self.assertEqual(
            recent_oracle["retained_journal_ids"],
            [
                record["record_id"]
                for record in recent["store"]["journal"]
            ],
        )
        self.assertEqual(
            recent_oracle["retained_recent_ids"],
            recent["store"]["recently_pruned_record_ids"],
        )
        self.assertNotIn(
            recent_oracle["evicted_recent_ids"][0],
            recent["store"]["recently_pruned_record_ids"],
        )
        self.assertEqual(
            recent_oracle["recent_id_count_after"],
            len(recent["store"]["recently_pruned_record_ids"]),
        )

    def test_byte_retention_and_required_evidence_failure(self):
        abstract_case = self.cases[
            "store_byte_cap_prunes_oldest_full_record"
        ]
        required_case = self.cases[
            "required_state_exceeds_byte_cap_fails"
        ]

        store = new_state_store(INSTANCE_ID)
        for index, record_id in enumerate(
            ("record-oldest", "record-newer", "record-newest")
        ):
            store = propose_transition(
                store,
                "pre",
                _observation(
                    "obs-" + record_id,
                    "2026-07-30T12:00:0{0}Z".format(index),
                ),
                scope=SCOPE,
                record_id=record_id,
                journal_max_records=100,
            )["store"]
        full_bytes = len(canonical_store_bytes(store))
        once_pruned, ignored = apply_retention(
            store,
            protected_record_id="record-newest",
            journal_max_records=100,
            state_max_bytes=full_bytes - 1,
        )
        self.assertEqual(["record-oldest"], ignored)
        self.assertEqual(
            abstract_case["oracle"]["retained_record_ids"],
            [
                record["record_id"]
                for record in once_pruned["journal"]
            ],
        )
        self.assertLessEqual(
            len(canonical_store_bytes(once_pruned)), full_bytes - 1
        )

        protected = new_state_store(INSTANCE_ID)
        protected = propose_transition(
            protected,
            "pre",
            _observation(
                "obs-record-cannot-fit", "2026-07-30T12:00:00Z"
            ),
            scope=SCOPE,
            record_id=required_case["transaction"][
                "append_required_record"
            ]["record_id"],
        )["store"]
        before = canonical_store_bytes(protected)
        with self.assertRaises(TransitionError) as captured:
            apply_retention(
                protected,
                protected_record_id=required_case["transaction"][
                    "append_required_record"
                ]["record_id"],
                journal_max_records=100,
                state_max_bytes=len(before) - 1,
            )
        self.assertEqual(
            required_case["oracle"]["failure_reason"],
            captured.exception.reason,
        )
        self.assertEqual(
            required_case["oracle"]["persistence_outcome"],
            captured.exception.persistence_outcome,
        )
        self.assertEqual(before, canonical_store_bytes(protected))

    def test_canonical_known_answer_and_real_byte_pressure(self):
        known_case = self.cases[
            "canonical_complete_store_known_answer"
        ]
        store = copy.deepcopy(known_case["input"]["canonical_store"])
        encoded = canonical_store_bytes(store)
        digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
        oracle = known_case["oracle"]
        self.assertEqual(oracle["exact_serialized_bytes"], len(encoded))
        self.assertEqual(oracle["exact_sha256"], digest)
        self.assertEqual(
            store,
            decode_store_bytes(encoded, INSTANCE_ID, STATE_MAX_BYTES),
        )
        self.assertEqual(
            encoded,
            canonical_store_bytes(
                decode_store_bytes(
                    encoded, INSTANCE_ID, STATE_MAX_BYTES
                )
            ),
        )

        pressure_case = self.cases[
            "canonical_byte_pressure_prunes_real_serialization"
        ]
        candidate = copy.deepcopy(
            pressure_case["input"]["prior_store"]
        )
        candidate["revision"] = pressure_case["input"][
            "proposed_revision"
        ]
        candidate["journal"].append(
            copy.deepcopy(pressure_case["input"]["append_record"])
        )
        pre_prune = canonical_store_bytes(candidate)
        pressure_oracle = pressure_case["oracle"]
        self.assertEqual(
            pressure_oracle["exact_pre_prune_candidate_bytes"],
            len(pre_prune),
        )
        self.assertEqual(
            pressure_oracle["exact_pre_prune_sha256"],
            "sha256:" + hashlib.sha256(pre_prune).hexdigest(),
        )
        retained, pruned = apply_retention(
            candidate,
            protected_record_id=pressure_case["input"][
                "append_record"
            ]["record_id"],
            journal_max_records=100,
            state_max_bytes=pressure_case["input"]["state_max_bytes"],
            release_validation=True,
        )
        post_prune = canonical_store_bytes(retained)
        self.assertEqual(
            pressure_oracle["exact_post_prune_candidate_bytes"],
            len(post_prune),
        )
        self.assertEqual(
            pressure_oracle["exact_post_prune_sha256"],
            "sha256:" + hashlib.sha256(post_prune).hexdigest(),
        )
        self.assertEqual(
            pressure_oracle["pruned_record_ids"], pruned
        )
        self.assertEqual(
            pressure_oracle["retained_record_ids"],
            [record["record_id"] for record in retained["journal"]],
        )
        self.assertEqual(
            pressure_oracle["recently_pruned_record_ids_after"],
            retained["recently_pruned_record_ids"],
        )

    def test_all_invalid_known_store_mutations_fail_production_decode(self):
        case = self.cases["invalid_existing_store_fails_closed"]
        known = copy.deepcopy(
            self.cases["canonical_complete_store_known_answer"][
                "input"
            ]["canonical_store"]
        )
        rejected = []
        for variant in case["input"]["variants"]:
            variant_id = variant["id"]
            if "source_bytes" in variant:
                source = variant["source_bytes"].encode("utf-8")
            elif variant.get("source_encoding") == (
                "pretty_printed_json_plus_lf"
            ):
                source = (
                    json.dumps(
                        copy.deepcopy(variant["canonical_value"]),
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n"
                ).encode("utf-8")
            else:
                mutated = copy.deepcopy(
                    variant.get("canonical_value", known)
                )
                mutations = variant.get("mutations")
                if mutations is None:
                    mutations = [variant["mutation"]]
                for mutation in mutations:
                    _set_path(
                        mutated,
                        mutation["path"],
                        copy.deepcopy(mutation["value"]),
                    )
                source = canonical_json_bytes(mutated)
            with self.subTest(variant=variant_id):
                with self.assertRaises(PersistenceError) as captured:
                    decode_store_bytes(
                        source,
                        INSTANCE_ID,
                        STATE_MAX_BYTES,
                    )
                self.assertEqual(
                    case["oracle"]["failure_reason_for_each"],
                    captured.exception.reason,
                )
                self.assertEqual(
                    case["oracle"]["exception_text_returned_for_each"],
                    str(captured.exception) != "corrupt_state",
                )
            rejected.append(variant_id)
        self.assertEqual(
            case["oracle"]["variant_count"], len(rejected)
        )

    def test_lock_timeout_and_oversized_store_stop_before_state_use(self):
        timeout_case = self.cases["state_lock_timeout_is_bounded"]
        timeout_root = self.state_root("timeout")
        prior = _revision_store(
            timeout_case["input"]["prior_revision"]
        )
        normal = _backend(timeout_root)
        state_path = _write_store_file(normal, prior)
        with open(state_path, "rb") as stream:
            prior_bytes = stream.read()

        class ContendedFcntl(object):
            LOCK_EX = 1
            LOCK_NB = 2
            LOCK_UN = 8

            @staticmethod
            def flock(_descriptor, operation):
                if operation != ContendedFcntl.LOCK_UN:
                    raise OSError(errno.EAGAIN, "synthetic contention")

        readings = iter(timeout_case["input"]["monotonic_probe_seconds"])
        contended = _backend(
            timeout_root,
            fcntl_module=ContendedFcntl,
            monotonic=lambda: next(readings),
            sleeper=lambda _seconds: None,
        )
        with self.assertRaises(PersistenceError) as timeout:
            contended.load(
                STATE_MAX_BYTES, create_namespace=False
            )
        self.assertEqual(
            timeout_case["oracle"]["failure_reason"],
            timeout.exception.reason,
        )
        with open(state_path, "rb") as stream:
            self.assertEqual(prior_bytes, stream.read())

        oversized_case = self.cases[
            "oversized_existing_store_fails_before_parse"
        ]
        oversized_root = self.state_root("oversized")
        oversized_backend = _backend(oversized_root)
        oversized_backend.load(
            oversized_case["input"]["state_max_bytes"],
            create_namespace=True,
        )
        oversized_path = os.path.join(
            oversized_root, INSTANCE_ID, "state.json"
        )
        descriptor = os.open(
            oversized_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            os.ftruncate(
                descriptor,
                oversized_case["input"]["existing_state_bytes"],
            )
        finally:
            os.close(descriptor)
        before_stat = os.stat(oversized_path)
        with mock.patch(
            "module_utils.docker_ansible_summary.persistence.json.loads",
            side_effect=AssertionError("JSON parser must not run"),
        ) as parser:
            with self.assertRaises(PersistenceError) as oversized:
                oversized_backend.load(
                    oversized_case["input"]["state_max_bytes"],
                    create_namespace=False,
                )
        self.assertEqual(0, parser.call_count)
        self.assertEqual(
            oversized_case["oracle"]["failure_reason"],
            oversized.exception.reason,
        )
        after_stat = os.stat(oversized_path)
        self.assertEqual(before_stat.st_size, after_stat.st_size)
        self.assertEqual(
            oversized_case["input"]["existing_state_bytes"],
            after_stat.st_size,
        )


if __name__ == "__main__":
    unittest.main()
