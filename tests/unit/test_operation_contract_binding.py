# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Bind every focused operation-contract case to production behavior."""

from __future__ import absolute_import, division, print_function

import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

import yaml

from module_utils.docker_ansible_summary.engine import (
    OperationFailure,
    execute_operation,
)
from module_utils.docker_ansible_summary.persistence import PosixStateStore
from module_utils.docker_ansible_summary.result import (
    FAILURE_FIELDS,
    MACHINE_RESULT_FIELDS,
)
from module_utils.docker_ansible_summary.validation import (
    ValidationError,
    validate_correlation_id,
)


ROLE_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = (
    ROLE_ROOT
    / "tests"
    / "fixtures"
    / "conformance"
    / "focused"
    / "operation-contract.yml"
)
STATE_MAX_BYTES = 16777216


def _load_action_plugin():
    """Load the production action plugin against the smallest ActionBase seam."""

    class ActionBaseStub(object):
        def run(self, tmp=None, task_vars=None):
            return {}

    ansible_stub = types.ModuleType("ansible")
    ansible_stub.__path__ = []
    plugins_stub = types.ModuleType("ansible.plugins")
    plugins_stub.__path__ = []
    action_stub = types.ModuleType("ansible.plugins.action")
    action_stub.ActionBase = ActionBaseStub
    specification = importlib.util.spec_from_file_location(
        "das_operation_contract_action",
        str(ROLE_ROOT / "action_plugins" / "docker_ansible_summary.py"),
    )
    module = importlib.util.module_from_spec(specification)
    with mock.patch.dict(
        sys.modules,
        {
            "ansible": ansible_stub,
            "ansible.plugins": plugins_stub,
            "ansible.plugins.action": action_stub,
        },
    ):
        specification.loader.exec_module(module)
    return module


ACTION_PLUGIN = _load_action_plugin()


class _Task(object):
    action = "docker_ansible_summary"
    async_val = 0

    def __init__(self, arguments, check_mode=False):
        self.args = dict(arguments)
        self.check_mode = check_mode


class _PlayContext(object):
    check_mode = False


class _Display(object):
    def __init__(self, events):
        self.blocks = []
        self.events = events

    def display(self, block):
        self.events.append("display")
        self.blocks.append(block)


class _ExecuteProbe(object):
    def __init__(self, module_result, events):
        self.module_result = module_result
        self.events = events
        self.calls = []

    def __call__(self, **kwargs):
        self.events.append("module")
        self.calls.append(kwargs)
        return self.module_result


class _DiscoveryProbe(object):
    def __init__(self, observations=()):
        self.observations = list(observations)
        self.calls = 0

    def __call__(self, _scope, _timeout_seconds):
        self.calls += 1
        if not self.observations:
            raise AssertionError("discovery was not expected")
        return copy.deepcopy(self.observations.pop(0))


class _ForbiddenPersistence(object):
    calls = 0

    def __init__(self, *_args, **_kwargs):
        type(self).calls += 1
        raise AssertionError("state access was not expected")


def _persistence_factory(state_root, instance_id):
    return PosixStateStore(
        state_root,
        instance_id,
        trusted_root_uid=os.stat("/").st_uid,
    )


def _case(document, case_id):
    return next(case for case in document["cases"] if case["id"] == case_id)


def _production_observation(value):
    observation = copy.deepcopy(value)
    observation["discovery_backend"] = "docker_cli_v1"
    observation.setdefault("reason_code", None)
    observation.setdefault("warnings", [])
    return observation


def _public_inputs(invocation, state_root):
    inputs = {
        "enabled": invocation.get("enabled", True),
        "operation": invocation.get("operation"),
        "instance_id": invocation.get("instance_id"),
        "scope": invocation.get("scope"),
        "record_id": invocation.get("record_id"),
        "state_root": state_root,
    }
    for name in (
        "correlation_id",
        "failure_policy",
        "report_mode",
        "report_width",
    ):
        value = invocation.get(name)
        if value is not None and value != "omitted":
            inputs[name] = value
    return inputs


def _execute_fixture(
    invocation,
    state_root,
    observation=None,
    generated_record_id=None,
    persistence_factory=_persistence_factory,
    discovery=None,
):
    selected_discovery = discovery or _DiscoveryProbe(
        [] if observation is None else [_production_observation(observation)]
    )
    result = execute_operation(
        _public_inputs(invocation, state_root),
        check_mode=invocation.get("check_mode", False),
        discovery=selected_discovery,
        persistence_factory=persistence_factory,
        record_id_factory=(
            None
            if generated_record_id is None
            else lambda: generated_record_id
        ),
    )
    return result, selected_discovery


def _load_store(state_root, instance_id="fixture-instance"):
    return _persistence_factory(state_root, instance_id).load(
        STATE_MAX_BYTES,
        create_namespace=False,
    )


def _write(
    state_root,
    operation,
    observation,
    record_id=None,
    correlation_id=None,
    generated_record_id=None,
):
    invocation = {
        "operation": operation,
        "instance_id": "fixture-instance",
        "scope": observation["scope"]["patterns"],
        "record_id": record_id,
        "check_mode": False,
    }
    if correlation_id is not None:
        invocation["correlation_id"] = correlation_id
    return _execute_fixture(
        invocation,
        state_root,
        observation=observation,
        generated_record_id=generated_record_id,
    )[0]


def _seed_open_records(state_root, observation, count, prefix="seed-open"):
    for index in range(count):
        _write(
            state_root,
            "pre",
            observation,
            record_id="{0}-{1:03d}".format(prefix, index),
        )


def _seed_baseline(state_root, observation, generated_id="seed-baseline"):
    return _write(
        state_root,
        "post",
        observation,
        generated_record_id=generated_id,
    )


def _action_arguments(invocation, state_root):
    arguments = _public_inputs(invocation, state_root)
    arguments.pop("enabled", None)
    arguments["enabled"] = invocation.get("enabled", True)
    return arguments


def _run_action(invocation, state_root, module_result, check_mode=False):
    events = []
    display = _Display(events)
    execute = _ExecuteProbe(module_result, events)
    plugin = object.__new__(ACTION_PLUGIN.ActionModule)
    plugin._task = _Task(
        _action_arguments(invocation, state_root),
        check_mode=check_mode,
    )
    plugin._play_context = _PlayContext()
    plugin._display = display
    plugin._execute_module = execute
    original_render = plugin._render

    def observed_render(host, inputs, machine):
        events.append("render")
        return original_render(host, inputs, machine)

    plugin._render = observed_render
    with mock.patch.object(ACTION_PLUGIN.ActionBase, "run", return_value={}):
        result = plugin.run(
            task_vars={"inventory_hostname": "fixture.example"}
        )
    return result, display.blocks, events, execute.calls


def _observation_id(machine):
    observation = machine.get("observation")
    return None if observation is None else observation["observation_id"]


def _assert_subset(test, expected, actual, context):
    if isinstance(expected, dict):
        test.assertIsInstance(actual, dict, context)
        for key, value in expected.items():
            test.assertIn(key, actual, context)
            _assert_subset(
                test,
                value,
                actual[key],
                context + "." + str(key),
            )
        return
    test.assertEqual(expected, actual, context)


def _assert_machine(test, expected, machine, context):
    projected = dict(machine)
    projected["observation"] = _observation_id(machine)
    _assert_subset(test, expected, projected, context)


def _assert_failure(test, oracle, result):
    test.assertTrue(result["failed"])
    test.assertNotIn("observation", result)
    envelope = result["docker_ansible_summary_failure"]
    test.assertEqual(set(FAILURE_FIELDS), set(envelope))
    test.assertEqual(oracle["failure_reason"], envelope["failure_reason"])
    if "observation_reason" in oracle:
        test.assertEqual(
            oracle["observation_reason"],
            envelope["observation_reason"],
        )
    if "committed_result_replayable" in oracle:
        test.assertEqual(
            oracle["committed_result_replayable"],
            envelope["committed_result_replayable"],
        )
    test.assertLessEqual(
        len(
            json.dumps(
                result,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ),
        1024,
    )
    return envelope


class OperationContractFixtureBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with FIXTURE_PATH.open(encoding="utf-8") as stream:
            cls.fixture = yaml.safe_load(stream)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="das-operation-contract-"
        )
        self.state_root = os.path.join(self.temporary.name, "state")

    def tearDown(self):
        self.temporary.cleanup()

    def observation(self, key):
        return self.fixture["shared"][key]

    def test_disabled_short_circuit_binds_exact_result_and_zero_dependencies(self):
        case = _case(
            self.fixture, "disabled_short_circuits_before_validation"
        )
        invocation = dict(
            case["invocation"]["deliberately_invalid_unvalidated_inputs"]
        )
        invocation["enabled"] = False
        discovery = _DiscoveryProbe()
        _ForbiddenPersistence.calls = 0

        machine = execute_operation(
            invocation,
            discovery=discovery,
            persistence_factory=_ForbiddenPersistence,
        )

        self.assertEqual(case["oracle"]["machine_result"], machine)
        self.assertEqual(set(MACHINE_RESULT_FIELDS), set(machine))
        self.assertEqual(0, discovery.calls)
        self.assertEqual(0, _ForbiddenPersistence.calls)
        self.assertFalse(os.path.exists(self.state_root))

    def test_unavailable_pre_then_complete_post_binds_real_persistence(self):
        pre_case = _case(
            self.fixture, "absent_store_unavailable_pre_commits_open"
        )
        pre, pre_discovery = _execute_fixture(
            pre_case["invocation"],
            self.state_root,
            observation=pre_case["invocation"]["observation"],
            generated_record_id=pre_case["oracle"]["generated_record_id"],
        )
        pre_store = _load_store(self.state_root)
        pre_oracle = pre_case["oracle"]

        _assert_subset(
            self,
            pre_oracle["between_observation_delta"],
            pre["between_observation_delta"],
            pre_case["id"],
        )
        _assert_machine(
            self, pre_oracle["machine_result"], pre, pre_case["id"]
        )
        self.assertEqual(pre_oracle["revision_after"], pre_store["revision"])
        self.assertEqual(
            pre_oracle["expected_post_revision"],
            pre_store["journal"][0]["expected_post_revision"],
        )
        self.assertIsNone(pre_store["latest_complete_post"])
        self.assertEqual(1, pre_discovery.calls)

        post_case = _case(
            self.fixture,
            "complete_post_after_unavailable_pre_advances_baseline",
        )
        post, post_discovery = _execute_fixture(
            post_case["invocation"],
            self.state_root,
            observation=post_case["invocation"]["observation"],
        )
        post_store = _load_store(self.state_root)
        post_oracle = post_case["oracle"]

        _assert_subset(
            self,
            post_oracle["between_observation_delta"],
            post["between_observation_delta"],
            post_case["id"] + ".between",
        )
        _assert_subset(
            self,
            post_oracle["run_window_delta"],
            post["run_window_delta"],
            post_case["id"] + ".window",
        )
        _assert_machine(
            self, post_oracle["machine_result"], post, post_case["id"]
        )
        self.assertEqual(post_oracle["revision_after"], post_store["revision"])
        self.assertEqual(
            post_oracle["baseline_after"],
            post_store["latest_complete_post"]["observation_id"],
        )
        self.assertEqual(1, post_discovery.calls)

    def _seed_fail_policy_prior_state(self):
        _seed_baseline(self.state_root, self.observation("complete_a"))
        _seed_open_records(
            self.state_root,
            self.observation("unavailable_b"),
            10,
            prefix="seed-fail-policy",
        )
        self.assertEqual(11, _load_store(self.state_root)["revision"])

    def test_fail_after_report_and_replay_bind_commit_render_order_and_policy(self):
        commit_case = _case(
            self.fixture, "fail_after_report_commits_renders_then_fails"
        )
        self._seed_fail_policy_prior_state()
        machine, discovery = _execute_fixture(
            commit_case["invocation"],
            self.state_root,
            observation=commit_case["invocation"]["observation"],
        )
        result, blocks, events, calls = _run_action(
            commit_case["invocation"],
            self.state_root,
            {"changed": False, "_das_machine_result": machine},
        )
        oracle = commit_case["oracle"]
        store = _load_store(self.state_root)

        self.assertEqual(1, discovery.calls)
        self.assertEqual(1, len(calls))
        self.assertEqual(["module", "render", "display"], events)
        self.assertTrue(blocks)
        _assert_failure(self, oracle, result)
        self.assertEqual(oracle["revision_after"], store["revision"])
        self.assertEqual(
            oracle["baseline_after"],
            store["latest_complete_post"]["observation_id"],
        )
        self.assertEqual(
            oracle["journal_status"], machine["journal_status"]
        )
        self.assertEqual(
            oracle["persistence_outcome"],
            machine["persistence_outcome"],
        )

        replay_case = _case(
            self.fixture,
            "retained_noncomplete_replay_reapplies_failure_policy",
        )
        replay_discovery = _DiscoveryProbe()
        replay_machine, _ = _execute_fixture(
            replay_case["invocation"],
            self.state_root,
            discovery=replay_discovery,
        )
        replay_result, replay_blocks, replay_events, replay_calls = (
            _run_action(
                replay_case["invocation"],
                self.state_root,
                {
                    "changed": False,
                    "_das_machine_result": replay_machine,
                },
            )
        )
        replay_oracle = replay_case["oracle"]

        self.assertEqual(0, replay_discovery.calls)
        self.assertEqual(["module", "render", "display"], replay_events)
        self.assertEqual(1, len(replay_calls))
        self.assertTrue(replay_blocks)
        _assert_failure(self, replay_oracle, replay_result)
        self.assertEqual(
            replay_oracle["returned_observation"],
            _observation_id(replay_machine),
        )
        self.assertEqual(
            replay_oracle["replay_outcome"],
            replay_machine["replay_outcome"],
        )
        self.assertEqual(
            replay_oracle["persistence_outcome"],
            replay_machine["persistence_outcome"],
        )
        self.assertEqual(
            replay_oracle["revision_after"],
            _load_store(self.state_root)["revision"],
        )

    def test_pre_commit_and_store_free_check_status_paths(self):
        pre_case = _case(self.fixture, "pre_commits_open_record")
        _seed_baseline(self.state_root, self.observation("complete_a"))
        _seed_open_records(
            self.state_root,
            self.observation("unavailable_b"),
            6,
            prefix="seed-pre",
        )
        machine, discovery = _execute_fixture(
            pre_case["invocation"],
            self.state_root,
            observation=pre_case["invocation"]["observation"],
        )
        oracle = pre_case["oracle"]
        store = _load_store(self.state_root)
        _assert_subset(
            self,
            oracle["between_observation_delta"],
            machine["between_observation_delta"],
            pre_case["id"],
        )
        _assert_machine(
            self, oracle["machine_result"], machine, pre_case["id"]
        )
        self.assertEqual(oracle["revision_after"], store["revision"])
        self.assertEqual(
            oracle["expected_post_revision"],
            store["journal"][-1]["expected_post_revision"],
        )
        self.assertEqual(1, discovery.calls)

        store_free_ids = (
            "check_pre_is_independent_simulation",
            "check_post_is_independent_simulation",
            "check_post_supplied_record_id_is_not_looked_up",
        )
        for case_id in store_free_ids:
            case = _case(self.fixture, case_id)
            probe = _DiscoveryProbe(
                [_production_observation(case["invocation"]["observation"])]
            )
            _ForbiddenPersistence.calls = 0
            with self.subTest(case=case_id):
                actual, _ = _execute_fixture(
                    case["invocation"],
                    "/store/access/is/forbidden",
                    discovery=probe,
                    persistence_factory=_ForbiddenPersistence,
                )
                _assert_machine(
                    self,
                    case["oracle"]["machine_result"],
                    actual,
                    case_id,
                )
                self.assertEqual(1, probe.calls)
                self.assertEqual(0, _ForbiddenPersistence.calls)

        for case_id in (
            "check_post_noncomplete_fail_after_report_is_store_free",
            "status_noncomplete_fail_after_report_is_store_free",
        ):
            case = _case(self.fixture, case_id)
            probe = _DiscoveryProbe(
                [_production_observation(case["invocation"]["observation"])]
            )
            _ForbiddenPersistence.calls = 0
            machine, _ = _execute_fixture(
                case["invocation"],
                "/store/access/is/forbidden",
                discovery=probe,
                persistence_factory=_ForbiddenPersistence,
            )
            result, blocks, events, calls = _run_action(
                case["invocation"],
                "/store/access/is/forbidden",
                {"changed": False, "_das_machine_result": machine},
                check_mode=case["invocation"]["check_mode"],
            )
            with self.subTest(case=case_id):
                if "machine_result" in case["oracle"]:
                    _assert_machine(
                        self,
                        case["oracle"]["machine_result"],
                        machine,
                        case_id,
                    )
                envelope = _assert_failure(
                    self, case["oracle"], result
                )
                self.assertEqual(
                    case["oracle"]["persistence_outcome"],
                    machine["persistence_outcome"],
                )
                self.assertEqual(0, _ForbiddenPersistence.calls)
                self.assertEqual(1, probe.calls)
                self.assertEqual(1, len(calls))
                self.assertEqual(
                    ["module", "render", "display"], events
                )
                self.assertTrue(blocks)
                self.assertIsNone(envelope["record_id"])

        invalid_case = _case(
            self.fixture, "status_rejects_supplied_record_id"
        )
        invalid_result, blocks, events, calls = _run_action(
            invalid_case["invocation"],
            "/store/access/is/forbidden",
            AssertionError("invalid status must not invoke the module"),
        )
        envelope = _assert_failure(
            self, invalid_case["oracle"], invalid_result
        )
        self.assertEqual([], calls)
        self.assertEqual(["display"], events)
        self.assertTrue(blocks)
        self.assertIsNone(envelope["record_id"])
        self.assertEqual(
            invalid_case["oracle"]["persistence_outcome"],
            envelope["persistence_outcome"],
        )

    def test_scope_and_post_only_lifecycle_boundaries(self):
        incompatible = _case(
            self.fixture,
            "incompatible_a_to_b_with_compatible_b_to_c",
        )
        _seed_baseline(
            self.state_root, self.observation("incompatible_a")
        )
        _seed_open_records(
            self.state_root,
            self.observation("unavailable_b"),
            8,
            prefix="seed-incompatible",
        )
        _write(
            self.state_root,
            "pre",
            self.observation("complete_b"),
            record_id=incompatible["invocation"]["record_id"],
        )
        actual, _ = _execute_fixture(
            incompatible["invocation"],
            self.state_root,
            observation=incompatible["invocation"]["observation"],
        )
        oracle = incompatible["oracle"]
        _assert_subset(
            self,
            oracle["between_observation_delta"],
            actual["between_observation_delta"],
            incompatible["id"] + ".between",
        )
        _assert_subset(
            self,
            oracle["run_window_delta"],
            actual["run_window_delta"],
            incompatible["id"] + ".window",
        )
        self.assertEqual(oracle["journal_status"], actual["journal_status"])
        self.assertNotEqual(
            oracle["forbidden_journal_status"],
            actual["journal_status"],
        )
        self.assertEqual(
            oracle["baseline_after"],
            actual["baseline"]["after"],
        )

        for case_id, prior_revision in (
            ("deliberate_post_only_complete", 8),
            (
                "post_only_unavailable_commits_incomplete_both_without_deltas",
                9,
            ),
        ):
            case = _case(self.fixture, case_id)
            with tempfile.TemporaryDirectory(
                prefix="das-operation-post-only-"
            ) as temporary:
                root = os.path.join(temporary, "state")
                _seed_baseline(root, self.observation("complete_a"))
                _seed_open_records(
                    root,
                    self.observation("unavailable_b"),
                    prior_revision - 1,
                    prefix="seed-post-only",
                )
                actual, _ = _execute_fixture(
                    case["invocation"],
                    root,
                    observation=case["invocation"]["observation"],
                    generated_record_id="generated-post-only-001",
                )
                store = _load_store(root)
                oracle = case["oracle"]
                self.assertIsNotNone(actual["record_id"])
                self.assertIsNone(actual["between_observation_delta"])
                self.assertIsNone(actual["run_window_delta"])
                self.assertEqual(
                    oracle["baseline_advanced"],
                    actual["baseline_advanced"],
                )
                self.assertEqual(
                    oracle["baseline_after"],
                    actual["baseline"]["after"],
                )
                self.assertEqual(
                    oracle["journal_status"], actual["journal_status"]
                )
                if "persisted_record_projection" in oracle:
                    record = store["journal"][-1]
                    projection = {
                        "pre_signature": record["pre_signature"],
                        "pre": record["pre"],
                        "between_observation_delta": record[
                            "between_observation_delta"
                        ],
                        "pre_baseline": record["pre_baseline"],
                        "post_signature_present": (
                            record["post_signature"] is not None
                        ),
                        "post_observation_id": record["post"][
                            "observation_id"
                        ],
                        "run_window_delta": record["run_window_delta"],
                        "post_baseline": record["post_baseline"],
                    }
                    self.assertEqual(
                        oracle["persisted_record_projection"],
                        projection,
                    )

        conflict_case = _case(
            self.fixture, "pre_cannot_fill_retained_post_only_record"
        )
        with tempfile.TemporaryDirectory(
            prefix="das-operation-post-only-conflict-"
        ) as temporary:
            root = os.path.join(temporary, "state")
            _write(
                root,
                "post",
                self.observation("complete_c"),
                generated_record_id=conflict_case["invocation"][
                    "record_id"
                ],
            )
            _seed_open_records(
                root,
                self.observation("unavailable_b"),
                8,
                prefix="seed-retained-post-only",
            )
            before = _load_store(root)
            discovery = _DiscoveryProbe()
            with self.assertRaises(OperationFailure) as captured:
                _execute_fixture(
                    conflict_case["invocation"],
                    root,
                    discovery=discovery,
                )
            after = _load_store(root)
            self.assertEqual(
                conflict_case["oracle"]["failure_reason"],
                captured.exception.reason,
            )
            self.assertEqual(
                conflict_case["oracle"]["persistence_outcome"],
                captured.exception.persistence_outcome,
            )
            self.assertEqual(0, discovery.calls)
            self.assertEqual(before, after)
            self.assertEqual(
                conflict_case["oracle"]["revision_after"],
                after["revision"],
            )

        incomplete = _case(self.fixture, "incomplete_pre_and_post")
        with tempfile.TemporaryDirectory(
            prefix="das-operation-incomplete-"
        ) as temporary:
            root = os.path.join(temporary, "state")
            _seed_baseline(root, self.observation("complete_a"))
            _seed_open_records(
                root,
                self.observation("unavailable_b"),
                7,
                prefix="seed-incomplete",
            )
            _write(
                root,
                "pre",
                self.observation("partial_b"),
                record_id=incomplete["invocation"]["record_id"],
            )
            actual, _ = _execute_fixture(
                incomplete["invocation"],
                root,
                observation=incomplete["invocation"]["observation"],
            )
            oracle = incomplete["oracle"]
            _assert_subset(
                self,
                oracle["between_observation_delta"],
                actual["between_observation_delta"],
                incomplete["id"] + ".between",
            )
            _assert_subset(
                self,
                oracle["run_window_delta"],
                actual["run_window_delta"],
                incomplete["id"] + ".window",
            )
            self.assertEqual(
                oracle["journal_status"], actual["journal_status"]
            )
            self.assertEqual(
                oracle["baseline_after"], actual["baseline"]["after"]
            )

    def test_correlation_inheritance_conflict_and_grouping_semantics(self):
        inherited = _case(
            self.fixture, "correlation_inherits_to_matching_post_and_header"
        )
        _seed_open_records(
            self.state_root,
            self.observation("complete_b"),
            19,
            prefix="seed-correlation-inherit",
        )
        _write(
            self.state_root,
            "pre",
            self.observation("complete_b"),
            record_id=inherited["invocation"]["record_id"],
            correlation_id=inherited["oracle"]["correlation_id"],
        )
        machine, discovery = _execute_fixture(
            inherited["invocation"],
            self.state_root,
            observation=inherited["invocation"]["observation"],
        )
        result, blocks, events, calls = _run_action(
            inherited["invocation"],
            self.state_root,
            {"changed": False, "_das_machine_result": machine},
        )
        oracle = inherited["oracle"]
        self.assertEqual(1, discovery.calls)
        self.assertEqual(1, len(calls))
        self.assertEqual(["module", "render", "display"], events)
        self.assertFalse(result.get("failed", False))
        self.assertEqual(
            oracle["machine_result_correlation_id"],
            result["correlation_id"],
        )
        self.assertTrue(blocks)
        self.assertIn(oracle["report_header_correlation_id"], blocks[0])

        conflict = _case(
            self.fixture, "correlation_mismatch_conflicts_before_discovery"
        )
        with tempfile.TemporaryDirectory(
            prefix="das-operation-correlation-conflict-"
        ) as temporary:
            root = os.path.join(temporary, "state")
            _seed_open_records(
                root,
                self.observation("complete_b"),
                20,
                prefix="seed-correlation-conflict",
            )
            _write(
                root,
                "pre",
                self.observation("complete_b"),
                record_id=conflict["invocation"]["record_id"],
                correlation_id=conflict["prior_state"]["journal"][0][
                    "correlation_id"
                ],
            )
            before = _load_store(root)
            probe = _DiscoveryProbe()
            with self.assertRaises(OperationFailure) as captured:
                _execute_fixture(
                    conflict["invocation"],
                    root,
                    discovery=probe,
                )
            private = captured.exception.as_private_dict()
            action_result, _, _, _ = _run_action(
                conflict["invocation"],
                root,
                {
                    "changed": False,
                    "failed": True,
                    "_das_failure": private,
                },
            )
            envelope = action_result[
                "docker_ansible_summary_failure"
            ]
            self.assertEqual(
                conflict["oracle"]["failure_reason"],
                captured.exception.reason,
            )
            self.assertEqual(0, probe.calls)
            self.assertEqual(before, _load_store(root))
            self.assertNotIn("correlation_id", envelope)

        grouping = _case(
            self.fixture, "correlation_is_grouping_not_lookup"
        )
        with tempfile.TemporaryDirectory(
            prefix="das-operation-correlation-group-"
        ) as temporary:
            root = os.path.join(temporary, "state")
            _seed_open_records(
                root,
                self.observation("complete_b"),
                20,
                prefix="seed-correlation-group",
            )
            shared = grouping["invocation"]["correlation_id"]
            for record_id in (
                "record-correlation-a",
                "record-correlation-b",
            ):
                _write(
                    root,
                    "pre",
                    self.observation("complete_b"),
                    record_id=record_id,
                    correlation_id=shared,
                )
            actual, _ = _execute_fixture(
                grouping["invocation"],
                root,
                observation=grouping["invocation"]["observation"],
            )
            store = _load_store(root)
            statuses = {
                record["record_id"]: record["status"]
                for record in store["journal"]
            }
            oracle = grouping["oracle"]
            self.assertEqual(
                oracle["selected_record_id"], actual["record_id"]
            )
            self.assertEqual(
                oracle["unselected_record_status"][
                    "record-correlation-a"
                ],
                statuses["record-correlation-a"],
            )
            self.assertEqual(
                "complete", statuses["record-correlation-b"]
            )
            self.assertEqual(shared, actual["correlation_id"])

    def test_correlation_bounds_are_enforced_before_discovery(self):
        case = _case(
            self.fixture, "correlation_validation_is_bounded"
        )
        variants = case["invocation_variants"]
        oracle = case["oracle"]
        ascii_value = variants["valid_ascii"]["correlation_id"]
        boundary_recipe = variants["valid_utf8_boundary_recipe"]
        overflow_recipe = variants["invalid_utf8_overflow_recipe"]
        boundary = (
            boundary_recipe["character"] * boundary_recipe["repeat"]
        )
        overflow = overflow_recipe["character"] * overflow_recipe["repeat"]
        control = "prefix\nsuffix"

        self.assertEqual(ascii_value, validate_correlation_id(ascii_value))
        self.assertEqual(boundary, validate_correlation_id(boundary))
        self.assertEqual(
            oracle["maximum_utf8_bytes"],
            len(boundary.encode("utf-8")),
        )
        for value, expected_code in (
            (overflow, "too_long"),
            (control, "control_character"),
        ):
            with self.subTest(expected_code=expected_code):
                with self.assertRaises(ValidationError) as captured:
                    validate_correlation_id(value)
                self.assertEqual(expected_code, captured.exception.code)
                self.assertEqual(
                    "correlation_id", captured.exception.field
                )

        status_invocation = {
            "operation": "status",
            "instance_id": "fixture-instance",
            "scope": ["fixture-*"],
            "record_id": None,
            "check_mode": False,
            "correlation_id": ascii_value,
        }
        status, discovery = _execute_fixture(
            status_invocation,
            "/store/access/is/forbidden",
            observation=self.observation("complete_b"),
            persistence_factory=_ForbiddenPersistence,
        )
        self.assertEqual(1, discovery.calls)
        self.assertEqual(ascii_value, status["correlation_id"])

        for value in (overflow, control):
            invocation = dict(status_invocation)
            invocation["correlation_id"] = value
            result, _, events, calls = _run_action(
                invocation,
                "/store/access/is/forbidden",
                AssertionError("invalid correlation reached discovery"),
            )
            self.assertEqual([], calls)
            self.assertEqual(["display"], events)
            self.assertEqual(
                "invalid_input",
                result["docker_ansible_summary_failure"][
                    "failure_reason"
                ],
            )

    def test_fixture_inventory_is_exactly_the_bound_operation_contract(self):
        expected = {
            "absent_store_unavailable_pre_commits_open",
            "check_post_is_independent_simulation",
            "check_post_noncomplete_fail_after_report_is_store_free",
            "check_post_supplied_record_id_is_not_looked_up",
            "check_pre_is_independent_simulation",
            "complete_post_after_unavailable_pre_advances_baseline",
            "correlation_inherits_to_matching_post_and_header",
            "correlation_is_grouping_not_lookup",
            "correlation_mismatch_conflicts_before_discovery",
            "correlation_validation_is_bounded",
            "deliberate_post_only_complete",
            "disabled_short_circuits_before_validation",
            "fail_after_report_commits_renders_then_fails",
            "incompatible_a_to_b_with_compatible_b_to_c",
            "incomplete_pre_and_post",
            "post_only_unavailable_commits_incomplete_both_without_deltas",
            "pre_cannot_fill_retained_post_only_record",
            "pre_commits_open_record",
            "retained_noncomplete_replay_reapplies_failure_policy",
            "status_noncomplete_fail_after_report_is_store_free",
            "status_rejects_supplied_record_id",
        }
        self.assertEqual(
            expected,
            {case["id"] for case in self.fixture["cases"]},
        )


if __name__ == "__main__":
    unittest.main()
