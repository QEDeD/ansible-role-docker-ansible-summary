# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Bind role-owned conformance fixtures to the production implementation.

The fixture validator proves that the planning corpus is internally
consistent.  These tests provide the separate proof that selected fixture
inputs are actually consumed by the role implementation.
"""

from __future__ import absolute_import, division, print_function

import copy
import datetime
import json
import os
from pathlib import Path
import tempfile
import unittest

import yaml

from module_utils.docker_ansible_summary.action_support import failure_block
from module_utils.docker_ansible_summary.discovery import (
    _scope_matches,
    discover,
    normalize_inspect_item,
)
from module_utils.docker_ansible_summary.engine import (
    OperationFailure,
    execute_operation,
)
from module_utils.docker_ansible_summary.persistence import PosixStateStore
from module_utils.docker_ansible_summary.result import failure_result
from module_utils.docker_ansible_summary.transition import (
    new_state_store,
    propose_transition,
)
from module_utils.docker_ansible_summary.validation import (
    ValidationError,
    canonical_store_bytes,
    normalize_scope,
    validate_observation,
)


FIXTURE_ROOT = (
    Path(__file__).resolve().parents[1] / "fixtures" / "conformance"
)
_USE_INVOCATION_RECORD_ID = object()


def _load_fixture(relative_path):
    with (FIXTURE_ROOT / relative_path).open(encoding="utf-8") as stream:
        return yaml.safe_load(stream)


def _case_by_id(cases, case_id):
    return next(case for case in cases if case["id"] == case_id)


def _materialize_scope_recipe(recipe):
    patterns = []
    for index in range(recipe["count"]):
        pattern = (
            recipe["prefix"]
            + str(index).zfill(recipe["index_width"])
        )
        target_bytes = recipe.get("pattern_bytes")
        if target_bytes is not None:
            pattern += "x" * (target_bytes - len(pattern.encode("ascii")))
        patterns.append(pattern)
    return patterns


def _production_observation(document, key):
    """Project one synthetic scenario observation into the release backend."""

    observation = copy.deepcopy(document["observations"][key])
    observation.setdefault("reason_code", None)
    observation.setdefault("warnings", [])
    # ``synthetic`` is fixture provenance, not a release backend value.  The
    # observation evidence itself is preserved while exercising the closed
    # production transition and persistence validators.
    observation["discovery_backend"] = "docker_cli_v1"
    return observation


def _inspect_item(projection):
    """Expand a safe fixture projection to the exact Docker adapter shape."""

    return {
        "container_id": projection["container_id"],
        "created_at": projection.get(
            "created_at", "2026-07-30T09:00:00Z"
        ),
        "finished_at": projection.get(
            "finished_at", "0001-01-01T00:00:00Z"
        ),
        "full_image_reference": projection["full_image_reference"],
        "image_id": projection["image_id"],
        "name": projection["name"],
        "restart_count": projection.get("restart_count", 0),
        "runtime_state": projection.get(
            "raw_runtime_state", projection.get("runtime_state")
        ),
        "started_at": projection.get(
            "started_at", "0001-01-01T00:00:00Z"
        ),
    }


class DiscoverySequence(object):
    def __init__(self, observations):
        self.observations = list(observations)
        self.calls = 0

    def __call__(self, _scope, _timeout_seconds):
        self.calls += 1
        return copy.deepcopy(self.observations.pop(0))


class DockerTranscript(object):
    def __init__(self, stdout_payloads):
        self.stdout_payloads = list(stdout_payloads)
        self.calls = []

    def __call__(self, argv, timeout_seconds):
        self.calls.append((list(argv), timeout_seconds))
        return {
            "status": "ok",
            "returncode": 0,
            "stdout": self.stdout_payloads.pop(0),
            "stderr": b"",
        }


def _json_lines(*items):
    return "".join(
        json.dumps(item, separators=(",", ":")) + "\n"
        for item in items
    ).encode("utf-8")


def _local_persistence_factory(state_root, instance_id):
    return PosixStateStore(
        state_root,
        instance_id,
        trusted_root_uid=os.stat("/").st_uid,
    )


def _operation_inputs(
    state_root,
    invocation,
    operation=None,
    record_id=_USE_INVOCATION_RECORD_ID,
):
    return {
        "enabled": True,
        "operation": operation or invocation["operation"],
        "instance_id": invocation["instance_id"],
        "scope": invocation["scope"],
        "record_id": (
            invocation.get("record_id")
            if record_id is _USE_INVOCATION_RECORD_ID
            else record_id
        ),
        "state_root": state_root,
        "report_mode": "none",
    }


class NormalizationFixtureBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = _load_fixture("focused/normalization.yml")

    def test_scope_known_answers_and_matching_dialect(self):
        for case_id in (
            "scalar_scope",
            "sort_and_deduplicate",
            "explicit_all",
        ):
            case = _case_by_id(self.fixture["scope_cases"], case_id)
            actual = normalize_scope(case["input"])
            self.assertEqual(case["oracle"]["patterns"], actual["patterns"])
            self.assertEqual(case["oracle"]["identity"], actual["identity"])
            self.assertEqual(1, actual["comparison_schema_version"])

        dialect = _case_by_id(
            self.fixture["scope_cases"],
            "fnmatchcase_full_name_dialect",
        )
        normalized = normalize_scope(dialect["input"])
        self.assertEqual(
            dialect["oracle"]["patterns"], normalized["patterns"]
        )
        self.assertEqual(
            dialect["oracle"]["identity"], normalized["identity"]
        )
        for probe in dialect["oracle"]["probes"]:
            with self.subTest(probe=probe["name"]):
                self.assertEqual(
                    probe["matches"],
                    _scope_matches(probe["name"], normalized),
                )

    def test_invalid_scope_inputs_are_rejected_by_production_codes(self):
        expected = {
            "invalid_empty": "invalid_empty_scope",
            "invalid_whitespace_scalar": "invalid_empty_scope_entry",
            "invalid_mixed_empty_entry": "invalid_empty_scope_entry",
        }
        for case_id, expected_code in expected.items():
            case = _case_by_id(self.fixture["scope_cases"], case_id)
            with self.subTest(case=case_id):
                with self.assertRaises(ValidationError) as captured:
                    normalize_scope(case["input"])
                self.assertEqual(expected_code, captured.exception.code)

        character_case = _case_by_id(
            self.fixture["scope_cases"],
            "invalid_scope_pattern_characters",
        )
        variants = copy.deepcopy(character_case["input_variants"])
        variants["control_character"] = "prefix\nsuffix"
        expected_codes = {
            "slash": "forbidden_scope_character",
            "internal_whitespace": "forbidden_scope_character",
            "backslash": "forbidden_scope_character",
            "non_ascii": "non_printable_ascii",
            "control_character": "forbidden_scope_character",
        }
        for variant, value in variants.items():
            with self.subTest(variant=variant):
                with self.assertRaises(ValidationError) as captured:
                    normalize_scope(value)
                self.assertEqual(
                    expected_codes[variant], captured.exception.code
                )

    def test_scope_limit_recipes_hit_exact_boundaries(self):
        expected_overflow_codes = {
            "scope_pattern_item_byte_bound": "scope_pattern_too_long",
            "scope_pattern_count_bound": "scope_pattern_count_exceeded",
            "scope_pattern_total_byte_bound": (
                "scope_pattern_bytes_exceeded"
            ),
        }
        for case_id, expected_code in expected_overflow_codes.items():
            case = _case_by_id(self.fixture["scope_cases"], case_id)
            boundary_input = _materialize_scope_recipe(
                case["boundary_input_recipe"]
            )
            overflow_input = _materialize_scope_recipe(
                case["overflow_input_recipe"]
            )
            actual = normalize_scope(boundary_input)
            self.assertEqual(
                case["oracle"]["normalized_pattern_count"],
                len(actual["patterns"]),
            )
            self.assertEqual(
                case["oracle"]["normalized_total_bytes"],
                sum(
                    len(pattern.encode("ascii"))
                    for pattern in actual["patterns"]
                ),
            )
            self.assertEqual(case["oracle"]["identity"], actual["identity"])
            with self.subTest(case=case_id):
                with self.assertRaises(ValidationError) as captured:
                    normalize_scope(overflow_input)
                self.assertEqual(expected_code, captured.exception.code)

    def test_container_projection_known_answers_use_adapter_normalizer(self):
        directly_normalized = (
            "api_leading_slash_and_registry_port",
            "digest_reference_preserved",
            "untagged_reference_preserved",
            "raw_exited_normalizes_to_stopped",
            "docker_zero_time_sentinels_normalize_to_null",
        )
        for case_id in directly_normalized:
            case = _case_by_id(self.fixture["container_cases"], case_id)
            projection = case["safe_adapter_projection"]
            expected_name = case["oracle"]["name"]
            normalized, gaps, partial_reason = normalize_inspect_item(
                _inspect_item(projection),
                projection["container_id"],
                expected_name,
            )
            self.assertIsNone(partial_reason, case_id)
            for field, value in case["oracle"].items():
                if field in normalized:
                    self.assertEqual(
                        value,
                        normalized[field],
                        "%s.%s" % (case_id, field),
                    )
            if "metadata_gaps" in case["oracle"]:
                self.assertEqual(case["oracle"]["metadata_gaps"], gaps)

        unsupported = _case_by_id(
            self.fixture["container_cases"],
            "unknown_runtime_makes_observation_partial",
        )
        projection = unsupported["safe_adapter_projection"]
        normalized, gaps, partial_reason = normalize_inspect_item(
            _inspect_item(projection),
            projection["container_id"],
            unsupported["oracle"]["name"],
        )
        self.assertIsNone(normalized["runtime_state"])
        self.assertEqual(
            unsupported["oracle"]["reason_code"], partial_reason
        )
        self.assertEqual(unsupported["oracle"]["metadata_gaps"], gaps)

    def test_optional_evidence_variants_become_exact_gaps(self):
        case = _case_by_id(
            self.fixture["container_cases"],
            "invalid_optional_evidence_normalizes_to_gap",
        )
        required = case["required_projection"]
        for variant, mutation in case["input_variants"].items():
            projection = copy.deepcopy(required)
            projection[mutation["field"]] = mutation["raw_value"]
            normalized, gaps, partial_reason = normalize_inspect_item(
                _inspect_item(projection),
                required["container_id"],
                required["name"],
            )
            self.assertIsNone(partial_reason)
            oracle = case["oracle"][variant]
            self.assertEqual(
                oracle["normalized_value"],
                normalized[mutation["field"]],
            )
            self.assertEqual(oracle["metadata_gaps"], gaps)

    def test_partial_required_runtime_and_name_faults_bind_full_oracles(self):
        missing_case = _case_by_id(
            self.fixture["discovery_cases"],
            "selected_container_inspect_failure_is_partial",
        )
        unsupported_case = _case_by_id(
            self.fixture["container_cases"],
            "unknown_runtime_makes_observation_partial",
        )
        name_case = _case_by_id(
            self.fixture["discovery_cases"],
            "inspect_name_mismatch_is_scope_unknown",
        )
        cases = (
            (
                missing_case,
                missing_case["safe_adapter_input"]["list_result"][
                    "catalogue"
                ][0],
                missing_case["safe_adapter_input"][
                    "partial_container_projection"
                ],
                ["fixture-api"],
            ),
            (
                unsupported_case,
                {
                    "container_id": unsupported_case[
                        "safe_adapter_projection"
                    ]["container_id"],
                    "name": unsupported_case["oracle"]["name"],
                },
                unsupported_case["safe_adapter_projection"],
                [unsupported_case["oracle"]["name"]],
            ),
            (
                name_case,
                name_case["safe_adapter_input"]["list_result"][
                    "catalogue"
                ][0],
                name_case["safe_adapter_input"]["inspect_result"][
                    "projections"
                ][0],
                [],
            ),
        )
        for case, catalogue, projection, expected_names in cases:
            enriched = {
                "full_image_reference": "registry.example.test/das:v1",
                "image_id": "sha256:" + ("a" * 64),
                "runtime_state": "running",
            }
            enriched.update(projection)
            inspect_item = _inspect_item(enriched)
            transcript = DockerTranscript(
                (
                    _json_lines(
                        {
                            "id": catalogue["container_id"],
                            "name": catalogue["name"],
                        }
                    ),
                    _json_lines(inspect_item),
                )
            )
            requested_scope = case.get("requested_scope", ["*"])
            observation = discover(
                normalize_scope(requested_scope),
                30,
                docker_path="/fixture/docker",
                runner=transcript,
                wall_clock=lambda: datetime.datetime(
                    2026, 7, 30, 12, 0, 0
                ),
                monotonic=iter((10.0, 10.1, 10.2)).__next__,
                observation_id_factory=lambda: "fixture-observation",
            )
            oracle = case["oracle"]
            with self.subTest(case=case["id"]):
                self.assertEqual(
                    oracle["observation_status"], observation["status"]
                )
                self.assertEqual(
                    oracle["reason_code"], observation["reason_code"]
                )
                self.assertEqual(
                    oracle["metadata_gaps"],
                    observation["metadata_gaps"],
                )
                self.assertEqual(
                    expected_names,
                    list(observation["containers"]),
                )
                if expected_names:
                    container = observation["containers"][
                        expected_names[0]
                    ]
                    if "runtime_state" in oracle:
                        self.assertEqual(
                            oracle["runtime_state"],
                            container["runtime_state"],
                        )
                    if case["id"] == (
                        "selected_container_inspect_failure_is_partial"
                    ):
                        self.assertIsNone(container["image_id"])
                self.assertEqual(2, len(transcript.calls))
                validate_observation(observation, release=True)


class NumberedScenarioFixtureBindingTests(unittest.TestCase):
    def test_scenario_19_uses_real_namespaced_persistence(self):
        document = _load_fixture(
            "scenarios/19-multi-instance-isolation.yml"
        )
        invocation = document["invocation"]
        oracle = document["oracle"]
        observation_a = _production_observation(document, "a")
        observation_b = _production_observation(document, "b")
        observation_c = _production_observation(document, "c")

        with tempfile.TemporaryDirectory(
            prefix="das-conformance-19-"
        ) as temporary:
            os.chmod(temporary, 0o700)
            state_root = os.path.join(temporary, "state")

            execute_operation(
                _operation_inputs(
                    state_root,
                    invocation,
                    operation="post",
                    record_id=None,
                ),
                discovery=DiscoverySequence([observation_a]),
                persistence_factory=_local_persistence_factory,
                record_id_factory=lambda: "scenario-19-baseline",
            )
            execute_operation(
                _operation_inputs(
                    state_root,
                    invocation,
                    operation="pre",
                    record_id=invocation["record_id"],
                ),
                discovery=DiscoverySequence([observation_b]),
                persistence_factory=_local_persistence_factory,
            )

            other_instance = next(
                iter(document["prior_state"]["other_instances"])
            )
            other_invocation = dict(invocation)
            other_invocation["instance_id"] = other_instance
            execute_operation(
                _operation_inputs(
                    state_root,
                    other_invocation,
                    operation="post",
                    record_id=None,
                ),
                discovery=DiscoverySequence([observation_a]),
                persistence_factory=_local_persistence_factory,
                record_id_factory=lambda: "scenario-19-other",
            )
            other_backend = _local_persistence_factory(
                state_root, other_instance
            )
            other_before = other_backend.load(
                state_max_bytes=16777216,
                create_namespace=False,
            )
            other_bytes_before = canonical_store_bytes(other_before)

            result = execute_operation(
                _operation_inputs(state_root, invocation),
                discovery=DiscoverySequence([observation_c]),
                persistence_factory=_local_persistence_factory,
            )

            other_after = other_backend.load(
                state_max_bytes=16777216,
                create_namespace=False,
            )
            other_bytes_after = canonical_store_bytes(other_after)

        self.assertEqual(other_before, other_after)
        self.assertEqual(other_bytes_before, other_bytes_after)
        self.assertEqual(
            oracle["between_observation_delta"]["comparability"],
            result["between_observation_delta"]["comparability"],
        )
        self.assertEqual(
            oracle["between_observation_delta"]["changes"],
            result["between_observation_delta"]["changes"],
        )
        self.assertEqual(
            oracle["run_window_delta"]["comparability"],
            result["run_window_delta"]["comparability"],
        )
        self.assertEqual(
            [
                {
                    "container_name": change["container_name"],
                    "primary_kind": change["primary_kind"],
                    "kinds": change["kinds"],
                }
                for change in result["run_window_delta"]["changes"]
            ],
            oracle["run_window_delta"]["changes"],
        )
        self.assertEqual(oracle["baseline"], result["baseline"])
        self.assertEqual(
            oracle["journal"]["status"], result["journal_status"]
        )
        self.assertEqual(
            oracle["persistence"]["outcome"],
            result["persistence_outcome"],
        )
        machine_oracle = oracle["machine_result"]
        self.assertEqual(machine_oracle["operation"], result["operation"])
        self.assertEqual(machine_oracle["instance_id"], result["instance_id"])
        self.assertEqual(machine_oracle["record_id"], result["record_id"])
        self.assertEqual(
            machine_oracle["observation_status"],
            result["observation_status"],
        )
        self.assertEqual(
            document["observations"][machine_oracle["observation"]][
                "observation_id"
            ],
            result["observation"]["observation_id"],
        )
        self.assertEqual(
            machine_oracle["scope_identity"], result["scope_identity"]
        )
        self.assertEqual(
            machine_oracle["baseline_advanced"],
            result["baseline_advanced"],
        )

    def test_scenario_20_status_never_constructs_a_store(self):
        document = _load_fixture("scenarios/20-status-no-writes.yml")
        invocation = document["invocation"]
        oracle = document["oracle"]
        observation = _production_observation(document, "current")
        persistence_calls = []

        def forbidden_persistence(*arguments):
            persistence_calls.append(arguments)
            raise AssertionError("status constructed a persistence backend")

        discovery = DiscoverySequence([observation])
        result = execute_operation(
            _operation_inputs("/state/must/not/be/read", invocation),
            discovery=discovery,
            persistence_factory=forbidden_persistence,
        )

        self.assertEqual([], persistence_calls)
        self.assertEqual(1, discovery.calls)
        self.assertEqual(
            oracle["persistence"]["outcome"],
            result["persistence_outcome"],
        )
        self.assertIsNone(result["between_observation_delta"])
        self.assertIsNone(result["run_window_delta"])
        self.assertIsNone(result["baseline"])
        self.assertIsNone(result["journal_status"])
        machine_oracle = oracle["machine_result"]
        for field in (
            "schema_version",
            "operation",
            "instance_id",
            "record_id",
            "observation_status",
            "scope_identity",
            "baseline_advanced",
            "journal_status",
            "persistence_outcome",
        ):
            self.assertEqual(machine_oracle[field], result[field])
        self.assertEqual(
            document["observations"][machine_oracle["observation"]][
                "observation_id"
            ],
            result["observation"]["observation_id"],
        )

    def test_scenario_21_conflict_is_after_discovery_and_store_is_unchanged(self):
        document = _load_fixture(
            "scenarios/21-concurrent-writer-conflict.yml"
        )
        invocation = document["invocation"]
        oracle = document["oracle"]
        scope = normalize_scope(invocation["scope"])
        observation_a = _production_observation(document, "a")
        observation_b = _production_observation(document, "b")
        observation_c = _production_observation(document, "c")

        state = new_state_store(invocation["instance_id"])
        state = propose_transition(
            state,
            "post",
            observation_a,
            scope=scope,
            record_id=None,
            record_id_factory=lambda: "scenario-21-baseline",
            release_validation=True,
        )["store"]
        loaded_state = propose_transition(
            state,
            "pre",
            observation_b,
            scope=scope,
            record_id=invocation["record_id"],
            release_validation=True,
        )["store"]
        concurrent_state = copy.deepcopy(loaded_state)
        concurrent_state["revision"] += 1
        durable_before = canonical_store_bytes(concurrent_state)

        class ConcurrentBackend(object):
            def load(self, **_kwargs):
                return copy.deepcopy(loaded_state)

            def transact(
                self, expected_revision, state_max_bytes, builder
            ):
                self.expected_revision = expected_revision
                self.state_max_bytes = state_max_bytes
                return builder(copy.deepcopy(concurrent_state))

        backend = ConcurrentBackend()
        discovery = DiscoverySequence([observation_c])
        with self.assertRaises(OperationFailure) as captured:
            execute_operation(
                _operation_inputs("/unused/conformance-state", invocation),
                discovery=discovery,
                persistence_factory=lambda *_arguments: backend,
            )

        failure = captured.exception
        self.assertEqual(1, discovery.calls)
        self.assertEqual(
            oracle["failure_reason"], failure.reason
        )
        self.assertEqual(
            oracle["persistence"]["outcome"],
            failure.persistence_outcome,
        )
        self.assertEqual(
            oracle["machine_result"][
                "docker_ansible_summary_failure"
            ]["observation_status"],
            failure.observation_status,
        )
        self.assertEqual(
            durable_before, canonical_store_bytes(concurrent_state)
        )

        private = failure.as_private_dict()
        task_result = failure_result(
            "fixture-a.example.com",
            private["failure_reason"],
            instance_id=invocation["instance_id"],
            operation=invocation["operation"],
            record_id=private["record_id"],
            observation_status=private["observation_status"],
            observation_reason=private["observation_reason"],
            persistence_outcome=private["persistence_outcome"],
            committed_result_replayable=private[
                "committed_result_replayable"
            ],
            retry_unchanged_phase=private["retry_unchanged_phase"],
        )
        self.assertEqual(oracle["machine_result"], task_result)
        diagnostic = failure_block(
            "fixture-a.example.com",
            private["failure_reason"],
            instance_id=invocation["instance_id"],
            operation=invocation["operation"],
            record_id=private["record_id"],
            persistence_outcome=private["persistence_outcome"],
        )
        for message in oracle["human"]["minimum_messages"]:
            self.assertIn(message, diagnostic)
        compact = json.dumps(
            task_result,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.assertLessEqual(len(compact), 1024)


if __name__ == "__main__":
    unittest.main()
