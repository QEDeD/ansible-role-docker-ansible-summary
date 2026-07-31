# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Bind the focused execution-surface fixtures to release code.

The fixture validator checks the planning corpus itself.  This suite instead
feeds fixture values into the role's validation, discovery, action,
presentation, result, and persistence boundaries.
"""

from __future__ import absolute_import, division, print_function

import copy
import datetime
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

from module_utils.docker_ansible_summary.action_support import (
    compact_warning_block,
    detect_public_variable_error,
)
from module_utils.docker_ansible_summary.compare import compare_observations
from module_utils.docker_ansible_summary.discovery import (
    ARGV_MAX_BYTES,
    CATALOGUE_FORMAT,
    CATALOGUE_MAX_ROWS,
    CONTAINER_CHUNK_MAX_ITEMS,
    INSPECT_FORMAT,
    OUTPUT_LINE_MAX_BYTES,
    STDERR_MAX_BYTES,
    STDOUT_MAX_BYTES,
    InspectFault,
    argv_size,
    chunk_identifiers,
    discover,
)
from module_utils.docker_ansible_summary.engine import execute_operation
from module_utils.docker_ansible_summary.persistence import (
    LOCK_TIMEOUT_SECONDS,
    PosixStateStore,
)
from module_utils.docker_ansible_summary.report import build_report_model
from module_utils.docker_ansible_summary.render import render_report
from module_utils.docker_ansible_summary.result import (
    MACHINE_RESULT_FIELDS,
    build_machine_result,
)
from module_utils.docker_ansible_summary.validation import (
    DEFAULT_DISCOVERY_TIMEOUT_SECONDS,
    DEFAULT_FAILURE_POLICY,
    DEFAULT_JOURNAL_MAX_RECORDS,
    DEFAULT_REPORT_MODE,
    DEFAULT_REPORT_WIDTH,
    DEFAULT_STATE_MAX_BYTES,
    DEFAULT_STATE_ROOT,
    INSTANCE_ID_RE,
    PUBLIC_INPUT_NAMES,
    RECORD_ID_RE,
    REASON_WARNINGS,
    ValidationError,
    normalize_scope,
    phase_signature,
    validate_public_inputs,
)


ROLE_ROOT = Path(__file__).resolve().parents[2]
EXECUTION_FIXTURE = (
    ROLE_ROOT
    / "tests"
    / "fixtures"
    / "conformance"
    / "focused"
    / "execution-surface.yml"
)
PERSISTENCE_FIXTURE = (
    ROLE_ROOT
    / "tests"
    / "fixtures"
    / "conformance"
    / "focused"
    / "persistence.yml"
)
DOCKER = "/usr/bin/docker"


def _load(path):
    with path.open(encoding="utf-8") as stream:
        return yaml.safe_load(stream)


EXECUTION = _load(EXECUTION_FIXTURE)
PERSISTENCE = _load(PERSISTENCE_FIXTURE)


def _case(document, case_id):
    return next(item for item in document["cases"] if item["id"] == case_id)


def _result(process):
    return {
        "status": "ok",
        "returncode": process["returncode"],
        "stdout": process["stdout"].encode("utf-8"),
        "stderr": process["stderr"].encode("utf-8"),
    }


def _clock():
    return datetime.datetime(2026, 7, 30, 12, 55, 0)


def _monotonic():
    return 1000.0


def _scope(patterns=None):
    return normalize_scope(patterns or ["fixture-*"])


def _observation(
    observation_id,
    status="complete",
    containers=None,
    reason=None,
):
    if status == "unavailable":
        containers = None
    elif containers is None:
        containers = {}
    return {
        "observation_id": observation_id,
        "observed_at": "2026-07-30T12:55:00Z",
        "scope": _scope(),
        "status": status,
        "reason_code": reason,
        "warnings": [] if reason is None else [REASON_WARNINGS[reason]],
        "discovery_backend": "docker_cli_v1",
        "metadata_gaps": [],
        "containers": containers,
    }


def _container(name, ordinal):
    return {
        "name": name,
        "container_id": "%064x" % ordinal,
        "full_image_reference": "registry.example.invalid/app:%d" % ordinal,
        "image_id": "sha256:" + ("%064x" % (ordinal + 1000)),
        "runtime_state": "running",
        "created_at": "2026-07-30T12:00:00Z",
        "started_at": "2026-07-30T12:00:01Z",
        "finished_at": None,
        "restart_count": 0,
    }


class _CatalogueRunner(object):
    """Generate safe Docker protocol output while recording exact processes."""

    def __init__(self, listed, selected):
        self.calls = []
        self.rows = []
        for index in range(listed):
            name = (
                "fixture-%04d" % index
                if index < selected
                else "unrelated-%04d" % index
            )
            self.rows.append(
                {"id": "%064x" % index, "name": name}
            )
        self.names = {item["id"]: item["name"] for item in self.rows}

    def __call__(self, argv, timeout_seconds):
        self.calls.append((list(argv), timeout_seconds))
        if argv[1:3] == ["container", "ls"]:
            stdout = "".join(
                json.dumps(item, separators=(",", ":")) + "\n"
                for item in self.rows
            )
            return {
                "status": "ok",
                "returncode": 0,
                "stdout": stdout.encode("utf-8"),
                "stderr": b"",
            }
        identifiers = argv[5:]
        stdout = ""
        for identifier in identifiers:
            name = self.names[identifier]
            item = {
                "container_id": identifier,
                "created_at": "2026-07-30T11:00:00Z",
                "finished_at": "0001-01-01T00:00:00Z",
                "full_image_reference": "example.invalid/app:1",
                "image_id": "sha256:" + ("1" * 64),
                "name": "/" + name,
                "restart_count": 0,
                "runtime_state": "running",
                "started_at": "2026-07-30T11:00:01Z",
            }
            stdout += json.dumps(item, separators=(",", ":")) + "\n"
        return {
            "status": "ok",
            "returncode": 0,
            "stdout": stdout.encode("utf-8"),
            "stderr": b"",
        }


class _SequenceRunner(object):
    def __init__(self, results, events=None):
        self.results = list(results)
        self.calls = []
        self.events = events

    def __call__(self, argv, timeout_seconds):
        self.calls.append((list(argv), timeout_seconds))
        if self.events is not None:
            self.events.append(
                "catalogue" if argv[1:3] == ["container", "ls"] else "inspect"
            )
        return self.results.pop(0)


class PublicAndRoleSurfaceBindingTests(unittest.TestCase):
    def test_public_contract_and_internal_constants_are_release_values(self):
        case = _case(EXECUTION, "public_input_contract_is_frozen")
        public = case["public_variables"]
        self.assertEqual(
            case["oracle"]["exact_public_variable_count"],
            len(PUBLIC_INPUT_NAMES),
        )
        self.assertEqual(
            set(public),
            {"docker_ansible_summary_" + name for name in PUBLIC_INPUT_NAMES},
        )

        defaults = {
            "docker_ansible_summary_enabled": True,
            "docker_ansible_summary_state_root": DEFAULT_STATE_ROOT,
            "docker_ansible_summary_journal_max_records": (
                DEFAULT_JOURNAL_MAX_RECORDS
            ),
            "docker_ansible_summary_state_max_bytes": DEFAULT_STATE_MAX_BYTES,
            "docker_ansible_summary_report_mode": DEFAULT_REPORT_MODE,
            "docker_ansible_summary_report_width": DEFAULT_REPORT_WIDTH,
            "docker_ansible_summary_discovery_timeout_seconds": (
                DEFAULT_DISCOVERY_TIMEOUT_SECONDS
            ),
            "docker_ansible_summary_failure_policy": DEFAULT_FAILURE_POLICY,
        }
        expected_defaults = {
            name: contract["default"]
            for name, contract in public.items()
            if contract["presence"] == "defaulted"
        }
        self.assertEqual(expected_defaults, defaults)
        self.assertEqual(
            public["docker_ansible_summary_instance_id"]["pattern"],
            INSTANCE_ID_RE.pattern[len(r"\A"):-len(r"\Z")],
        )
        self.assertEqual(
            public["docker_ansible_summary_record_id"]["pattern"],
            RECORD_ID_RE.pattern[len(r"\A"):-len(r"\Z")],
        )
        self.assertEqual(
            {
                "container_chunk_max_items": CONTAINER_CHUNK_MAX_ITEMS,
                "complete_argv_max_bytes": ARGV_MAX_BYTES,
                "state_lock_timeout_seconds": LOCK_TIMEOUT_SECONDS,
            },
            case["internal_constants"],
        )

        inputs = validate_public_inputs(
            {
                "enabled": True,
                "operation": "status",
                "instance_id": "fixture-mdad",
                "scope": ["fixture-*"],
            }
        )
        self.assertEqual(DEFAULT_REPORT_MODE, inputs["report_mode"])
        self.assertEqual(DEFAULT_STATE_ROOT, inputs["state_root"])
        for invalid in (
            {"enabled": True, "operation": "status", "instance_id": "x",
             "scope": "*", "unknown": True},
            {"docker_summary_mode": "status"},
        ):
            with self.assertRaises(ValidationError):
                validate_public_inputs(invalid)
        self.assertIsNone(
            detect_public_variable_error(
                {"enabled": True},
                {"docker_ansible_summary_result": {"record_id": "old"}},
            )
        )

    def test_state_and_deadline_bounds_are_enforced(self):
        limits = EXECUTION["state_and_deadline_limits"]
        base = {
            "enabled": True,
            "operation": "status",
            "instance_id": "fixture-mdad",
            "scope": "*",
        }
        accepted = dict(base)
        accepted.update(
            {
                "state_max_bytes": limits["minimum_state_max_bytes"],
                "discovery_timeout_seconds": 1,
            }
        )
        self.assertTrue(validate_public_inputs(accepted)["enabled"])
        for name, value in (
            ("state_max_bytes", limits["minimum_state_max_bytes"] - 1),
            ("state_max_bytes", limits["maximum_state_max_bytes"] + 1),
            ("discovery_timeout_seconds", 0),
            ("discovery_timeout_seconds", 301),
        ):
            candidate = dict(base)
            candidate[name] = value
            with self.subTest(name=name, value=value):
                with self.assertRaises(ValidationError):
                    validate_public_inputs(candidate)

    def test_role_has_one_static_task_and_direct_registered_projection(self):
        observe = (ROLE_ROOT / "tasks" / "observe.yml").read_text()
        main = (ROLE_ROOT / "tasks" / "main.yml").read_text()
        handoff = _case(
            EXECUTION, "static_import_repeated_handoff_is_host_local"
        )
        self.assertEqual(1, observe.count("- name:"))
        self.assertIn(
            "register: " + handoff["input"]["registered_result_name"],
            observe,
        )
        self.assertNotIn(
            handoff["oracle"]["forbidden_nested_record_id_path"],
            observe,
        )
        self.assertIn("ansible.builtin.import_tasks: observe.yml", main)
        self.assertFalse((ROLE_ROOT / "vars" / "main.yml").exists())


class DiscoveryExecutionBindingTests(unittest.TestCase):
    def _exercise_scale_case(self, case_id):
        case = _case(EXECUTION, case_id)
        source = case["input"]
        runner = _CatalogueRunner(
            source["listed_container_ids"],
            source["selected_container_ids"],
        )
        observation = discover(
            _scope(),
            30,
            docker_path=DOCKER,
            runner=runner,
            wall_clock=_clock,
            monotonic=_monotonic,
            observation_id_factory=lambda: "obs-" + case_id,
        )
        self.assertEqual("complete", observation["status"])
        self.assertEqual(
            source["selected_container_ids"],
            len(observation["containers"]),
        )
        inspect_calls = [
            call for call in runner.calls
            if call[0][1:3] == ["container", "inspect"]
        ]
        self.assertEqual(
            case["expected_chunks"]["container_inspect"],
            len(inspect_calls),
        )
        self.assertEqual(
            case["oracle"]["docker_processes"]["total"],
            len(runner.calls),
        )
        inspected = [
            identifier
            for call, _timeout in inspect_calls
            for identifier in call[5:]
        ]
        self.assertEqual(
            ["%064x" % index for index in range(source["selected_container_ids"])],
            inspected,
        )

    def test_scope_first_chunk_and_process_counts_match_fixture_cases(self):
        for case_id in (
            "complete_pre_default_is_quiet",
            "complete_post_emits_one_final_block",
            "status_emits_one_store_free_block",
            "large_catalogue_task_count_is_constant",
            "synthetic_scaling_guard_100_to_1000",
        ):
            with self.subTest(case=case_id):
                self._exercise_scale_case(case_id)

    def test_complete_empty_uses_only_the_catalogue_process(self):
        case = _case(
            EXECUTION, "complete_empty_uses_only_catalogue_process"
        )
        runner = _CatalogueRunner(0, 0)
        observation = discover(
            _scope(),
            30,
            docker_path=DOCKER,
            runner=runner,
            wall_clock=_clock,
            monotonic=_monotonic,
            observation_id_factory=lambda: "obs-empty",
        )
        self.assertEqual({}, observation["containers"])
        self.assertEqual(case["oracle"]["docker_processes"]["total"], 1)
        self.assertEqual(1, len(runner.calls))

    def test_argument_byte_limit_case_uses_complete_argv_bytes(self):
        case = _case(
            EXECUTION, "argument_byte_limit_splits_before_item_limit"
        )
        source = case["input"]
        chunks = chunk_identifiers(
            source["fixed_argv"],
            source["container_identifiers"],
            max_items=CONTAINER_CHUNK_MAX_ITEMS,
            max_bytes=source["fixture_internal_argument_byte_limit_bytes"],
        )
        self.assertEqual(
            case["expected_chunks"]["container_inspect"], len(chunks)
        )
        self.assertEqual(
            case["oracle"]["chunk_identifier_suffixes"],
            ["".join(identifier[-1] for identifier in chunk) for chunk in chunks],
        )
        self.assertEqual(
            case["oracle"]["complete_argv_bytes_by_chunk"],
            [argv_size(source["fixed_argv"] + chunk) for chunk in chunks],
        )
        self.assertEqual(
            source["container_identifiers"],
            [identifier for chunk in chunks for identifier in chunk],
        )

    def test_oversize_identifier_is_rejected_before_process_invocation(self):
        case = _case(
            EXECUTION, "oversize_identifier_is_not_invoked_or_echoed"
        )
        source = case["input"]
        self.assertEqual(
            case["oracle"]["minimum_complete_argv_bytes"],
            argv_size(source["fixed_argv"] + source["container_identifiers"]),
        )
        with self.assertRaises(InspectFault) as captured:
            chunk_identifiers(
                source["fixed_argv"],
                source["container_identifiers"],
                max_bytes=source[
                    "fixture_internal_argument_byte_limit_bytes"
                ],
            )
        self.assertEqual(case["oracle"]["reason_code"], captured.exception.reason)
        self.assertNotIn(source["container_identifiers"][0], str(captured.exception))

    def test_production_argv_and_caps_are_exact(self):
        case = _case(
            EXECUTION, "production_docker_argv_projection_and_caps_are_exact"
        )
        source = case["input"]
        oracle = case["oracle"]
        catalogue = [
            DOCKER,
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--format",
            CATALOGUE_FORMAT,
        ]
        inspect = [
            DOCKER,
            "container",
            "inspect",
            "--format",
            INSPECT_FORMAT,
        ]
        identifiers = [
            "%064x" % index
            for index in range(source["container_id_recipe"]["count"])
        ]
        self.assertEqual(source["catalogue_argv"], catalogue)
        self.assertEqual(source["inspect_fixed_argv"], inspect)
        self.assertEqual(oracle["catalogue_argv_bytes"], argv_size(catalogue))
        self.assertEqual(oracle["inspect_fixed_argv_bytes"], argv_size(inspect))
        self.assertEqual(
            oracle["inspect_argv_bytes_at_100_ids"],
            argv_size(inspect + identifiers),
        )
        self.assertEqual(
            {
                "complete_argv_max_bytes": ARGV_MAX_BYTES,
                "container_ids_per_chunk_max": CONTAINER_CHUNK_MAX_ITEMS,
                "catalogue_rows_max": CATALOGUE_MAX_ROWS,
                "subprocess_stdout_max_bytes": STDOUT_MAX_BYTES,
                "subprocess_stderr_max_bytes": STDERR_MAX_BYTES,
                "logical_output_line_max_bytes": OUTPUT_LINE_MAX_BYTES,
            },
            {
                key: oracle[key]
                for key in (
                    "complete_argv_max_bytes",
                    "container_ids_per_chunk_max",
                    "catalogue_rows_max",
                    "subprocess_stdout_max_bytes",
                    "subprocess_stderr_max_bytes",
                    "logical_output_line_max_bytes",
                )
            },
        )

    def test_fixture_transcript_projects_only_selected_safe_evidence(self):
        case = _case(
            EXECUTION, "fake_docker_transcript_projects_one_selected_container"
        )
        runner = _SequenceRunner(
            [_result(process) for process in case["input"]["processes"]]
        )
        observation = discover(
            _scope(case["input"]["normalized_scope"]),
            30,
            docker_path=DOCKER,
            runner=runner,
            wall_clock=_clock,
            monotonic=_monotonic,
            observation_id_factory=lambda: "obs-transcript",
        )
        oracle = case["oracle"]
        self.assertEqual(
            [process["argv"] for process in case["input"]["processes"]],
            [call[0] for call in runner.calls],
        )
        self.assertEqual(
            oracle["normalized_container"],
            observation["containers"]["fixture-api"],
        )
        self.assertEqual(oracle["observation_status"], observation["status"])
        self.assertEqual(oracle["reason_code"], observation["reason_code"])
        self.assertEqual(oracle["metadata_gaps"], observation["metadata_gaps"])
        serialized = json.dumps(observation)
        self.assertNotIn("SYNTHETIC_CANARY_DO_NOT_RETURN", serialized)
        self.assertNotIn("stdout", serialized)
        self.assertNotIn("stderr", serialized)

    def test_fixture_no_such_object_race_is_partial_without_raw_output(self):
        case = _case(
            EXECUTION, "fake_docker_no_such_object_race_is_partial"
        )
        container_id = case["input"]["requested_container_id"]
        catalogue = {
            "status": "ok",
            "returncode": 0,
            "stdout": (
                json.dumps({"id": container_id, "name": "fixture-api"}) + "\n"
            ).encode("utf-8"),
            "stderr": b"",
        }
        runner = _SequenceRunner(
            [catalogue, _result(case["input"]["process"])]
        )
        observation = discover(
            _scope(),
            30,
            docker_path=DOCKER,
            runner=runner,
            wall_clock=_clock,
            monotonic=_monotonic,
            observation_id_factory=lambda: "obs-race",
        )
        oracle = case["oracle"]
        self.assertEqual(oracle["observation_status"], observation["status"])
        self.assertEqual(oracle["reason_code"], observation["reason_code"])
        self.assertEqual(oracle["metadata_gaps"], observation["metadata_gaps"])
        self.assertEqual([oracle["generated_warning"]], observation["warnings"])
        self.assertNotIn(container_id, json.dumps(observation))

    def test_successful_catalogue_stderr_is_discarded(self):
        case = _case(
            EXECUTION, "fake_docker_success_with_bounded_stderr_is_accepted"
        )
        runner = _SequenceRunner([_result(case["input"]["process"])])
        observation = discover(
            _scope(),
            30,
            docker_path=DOCKER,
            runner=runner,
            wall_clock=_clock,
            monotonic=_monotonic,
            observation_id_factory=lambda: "obs-stderr",
        )
        oracle = case["oracle"]
        self.assertEqual(oracle["observation_status"], observation["status"])
        self.assertEqual(oracle["reason_code"], observation["reason_code"])
        self.assertEqual(oracle["containers"], observation["containers"])
        self.assertEqual(oracle["generated_warnings"], observation["warnings"])
        self.assertNotIn("deprecation", json.dumps(observation))

    def test_observed_at_precedes_one_deadline_and_docker_processes(self):
        case = _case(
            EXECUTION, "observed_at_opens_bounded_sampling_interval"
        )
        events = []

        def wall_clock():
            events.append("capture_observed_at")
            return datetime.datetime(2026, 7, 30, 12, 55, 0)

        def monotonic():
            events.append("monotonic")
            return 1000.0

        catalogue = {
            "status": "ok",
            "returncode": 0,
            "stdout": (
                json.dumps({"id": "a" * 64, "name": "fixture-api"}) + "\n"
            ).encode("utf-8"),
            "stderr": b"",
        }
        inspect = _result(
            _case(
                EXECUTION,
                "fake_docker_transcript_projects_one_selected_container",
            )["input"]["processes"][1]
        )
        runner = _SequenceRunner([catalogue, inspect], events=events)
        observation = discover(
            _scope(),
            case["input"]["discovery_timeout_seconds"],
            docker_path=DOCKER,
            runner=runner,
            wall_clock=wall_clock,
            monotonic=monotonic,
            observation_id_factory=lambda: "obs-interval",
        )
        self.assertEqual(case["oracle"]["observed_at"], observation["observed_at"])
        self.assertEqual(1, events.count("capture_observed_at"))
        self.assertLess(
            events.index("capture_observed_at"), events.index("catalogue")
        )
        self.assertLess(events.index("catalogue"), events.index("inspect"))


class _ActionBaseStub(object):
    def run(self, tmp=None, task_vars=None):
        return {}


_ANSIBLE_STUB = types.ModuleType("ansible")
_ANSIBLE_STUB.__path__ = []
_PLUGINS_STUB = types.ModuleType("ansible.plugins")
_PLUGINS_STUB.__path__ = []
_ACTION_STUB = types.ModuleType("ansible.plugins.action")
_ACTION_STUB.ActionBase = _ActionBaseStub
_PLUGIN_PATH = ROLE_ROOT / "action_plugins" / "docker_ansible_summary.py"
_SPECIFICATION = importlib.util.spec_from_file_location(
    "das_execution_fixture_action_plugin", str(_PLUGIN_PATH)
)
ACTION_PLUGIN = importlib.util.module_from_spec(_SPECIFICATION)
with mock.patch.dict(
    sys.modules,
    {
        "ansible": _ANSIBLE_STUB,
        "ansible.plugins": _PLUGINS_STUB,
        "ansible.plugins.action": _ACTION_STUB,
    },
):
    _SPECIFICATION.loader.exec_module(ACTION_PLUGIN)


class _Task(object):
    action = "docker_ansible_summary"
    async_val = 0

    def __init__(self, arguments, check_mode=False):
        self.args = dict(arguments)
        self.check_mode = check_mode


class _PlayContext(object):
    check_mode = False


class _Display(object):
    def __init__(self, events=None):
        self.blocks = []
        self.events = events

    def display(self, block):
        if self.events is not None:
            self.events.append("display_and_finalize")
        self.blocks.append(block)


class _Execute(object):
    def __init__(self, result, events=None):
        self.result = result
        self.calls = []
        self.events = events

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        if self.events is not None:
            self.events.append("observe_compare_and_commit")
        return self.result


def _action_plugin(arguments, module_result, check_mode=False, events=None):
    plugin = object.__new__(ACTION_PLUGIN.ActionModule)
    plugin._task = _Task(arguments, check_mode=check_mode)
    plugin._play_context = _PlayContext()
    plugin._display = _Display(events=events)
    execute = _Execute(module_result, events=events)
    plugin._execute_module = execute
    return plugin, execute


def _run_action(plugin, host="fixture-a.example.com"):
    with mock.patch.object(ACTION_PLUGIN.ActionBase, "run", return_value={}):
        return plugin.run(task_vars={"inventory_hostname": host})


def _module_success(machine):
    return {
        "changed": False,
        "_das_machine_result": machine,
        "invocation": {"module_args": {"private": "canary"}},
        "stdout": "private-canary",
        "stderr": "private-canary",
    }


def _simulated_machine(
    operation, status="complete", reason=None, check_mode=True
):
    inputs = {
        "enabled": True,
        "operation": operation,
        "instance_id": "fixture-mdad",
        "scope": ["fixture-*"],
        "report_mode": "none",
    }
    return execute_operation(
        inputs,
        check_mode=check_mode,
        discovery=lambda _scope_value, _timeout: _observation(
            "obs-simulated-" + operation,
            status=status,
            reason=reason,
        ),
    )


class ActionAndPresentationBindingTests(unittest.TestCase):
    def test_disabled_and_missing_input_short_circuit_before_module(self):
        disabled = _case(
            EXECUTION, "disabled_short_circuit_has_no_work"
        )
        plugin, execute = _action_plugin(
            {"enabled": False},
            AssertionError("module must not be invoked"),
        )
        result = _run_action(plugin)
        self.assertEqual(disabled["oracle"]["remote_module_invocations"], 0)
        self.assertEqual([], execute.calls)
        self.assertEqual([], plugin._display.blocks)
        self.assertEqual(
            disabled["oracle"]["machine_result_status"],
            "skipped" if result["skipped"] else "not-skipped",
        )

        missing = _case(
            EXECUTION, "enabled_missing_inputs_fails_before_module"
        )
        plugin, execute = _action_plugin(
            {"enabled": True},
            AssertionError("module must not be invoked"),
        )
        result = _run_action(plugin)
        self.assertEqual([], execute.calls)
        self.assertTrue(result["failed"])
        self.assertEqual(
            missing["oracle"]["failure_reason"],
            result["docker_ansible_summary_failure"]["failure_reason"],
        )
        self.assertEqual(
            missing["oracle"]["controller_display_actions"],
            len(plugin._display.blocks),
        )
        self.assertIn("values omitted", plugin._display.blocks[0])

    def test_machine_module_result_is_projected_from_the_exact_allowlist(self):
        case = _case(EXECUTION, "module_result_is_sanitized")
        machine = _simulated_machine("status", check_mode=False)
        plugin, execute = _action_plugin(
            {
                "enabled": True,
                "operation": "status",
                "instance_id": "fixture-mdad",
                "scope": ["fixture-*"],
                "report_mode": "none",
            },
            _module_success(machine),
        )
        result = _run_action(plugin)
        self.assertEqual(1, len(execute.calls))
        self.assertEqual(
            set(case["oracle"]["exact_role_authored_top_level_keys"]),
            set(result),
        )
        self.assertEqual(
            case["oracle"]["exact_machine_field_count"],
            len(MACHINE_RESULT_FIELDS),
        )
        for key in case["oracle"]["forbidden_returned_keys"]:
            self.assertNotIn(key, result)
        self.assertNotIn("private-canary", json.dumps(result))

    def test_report_modes_bind_module_and_controller_display_counts(self):
        cases = (
            ("complete_pre_default_is_quiet", "pre", "final", 0),
            ("complete_post_emits_one_final_block", "post", "final", 1),
            ("status_emits_one_store_free_block", "status", "final", 1),
            ("each_mode_pre_emits_one_block", "pre", "each", 1),
            ("none_mode_suppresses_table_not_machine_result", "post", "none", 0),
        )
        for case_id, operation, report_mode, expected_displays in cases:
            with self.subTest(case=case_id):
                case = _case(EXECUTION, case_id)
                machine = _simulated_machine(operation)
                plugin, execute = _action_plugin(
                    {
                        "enabled": True,
                        "operation": operation,
                        "instance_id": "fixture-mdad",
                        "scope": ["fixture-*"],
                        "report_mode": report_mode,
                    },
                    _module_success(machine),
                    check_mode=True,
                )
                result = _run_action(plugin)
                self.assertEqual(
                    case["oracle"]["remote_module_invocations"],
                    len(execute.calls),
                )
                self.assertEqual(expected_displays, len(plugin._display.blocks))
                self.assertEqual(
                    case["oracle"]["controller_display_actions"],
                    len(plugin._display.blocks),
                )
                self.assertFalse(result["changed"])

    def test_omitted_final_mode_renders_after_module_and_is_last(self):
        case = _case(
            EXECUTION, "omitted_report_mode_defaults_final_and_display_is_last"
        )
        machine = _simulated_machine("post")
        events = []
        plugin, execute = _action_plugin(
            {
                "enabled": True,
                "operation": "post",
                "instance_id": "fixture-mdad",
                "scope": ["fixture-*"],
            },
            _module_success(machine),
            check_mode=True,
            events=events,
        )
        result = _run_action(plugin)
        self.assertFalse(result["changed"])
        self.assertEqual(
            case["oracle"]["ordered_role_event_trace"], events
        )
        self.assertEqual(case["oracle"]["controller_display_actions"], 1)
        self.assertEqual(1, len(execute.calls))

    def test_exact_noncomplete_warning_matrix_uses_production_renderer(self):
        case = _case(
            EXECUTION, "none_mode_noncomplete_warning_matrix_is_exact"
        )
        source = case["input"]
        for variant, values in source["variants"].items():
            with self.subTest(variant=variant):
                machine = _simulated_machine(
                    values["operation"],
                    status=values["observation_status"],
                    reason=values["observation_reason"],
                )
                block = compact_warning_block(
                    machine,
                    source["host"],
                    source["report_mode"],
                    source["report_width"],
                )
                self.assertEqual(
                    case["oracle"]["exact_warning_blocks"][variant], block
                )
                self.assertEqual(
                    case["oracle"]["exact_warning_line_count_per_variant"],
                    len(block.splitlines()),
                )

    def test_none_mode_fail_after_report_returns_bounded_failure_after_warning(self):
        case = _case(
            EXECUTION,
            "none_mode_fail_after_report_keeps_minimum_safe_diagnostic",
        )
        machine = _simulated_machine(
            "post", status="unavailable", reason="docker_unavailable"
        )
        plugin, execute = _action_plugin(
            {
                "enabled": True,
                "operation": "post",
                "instance_id": "fixture-mdad",
                "scope": ["fixture-*"],
                "report_mode": "none",
                "failure_policy": "fail_after_report",
            },
            _module_success(machine),
            check_mode=True,
        )
        result = _run_action(plugin)
        envelope = result["docker_ansible_summary_failure"]
        self.assertEqual(1, len(execute.calls))
        self.assertEqual(
            case["oracle"]["controller_display_actions"],
            len(plugin._display.blocks),
        )
        self.assertTrue(plugin._display.blocks[0].startswith("DAS warning"))
        self.assertEqual(case["oracle"]["failure_reason"], envelope["failure_reason"])
        self.assertEqual(
            case["oracle"]["observation_reason"],
            envelope["observation_reason"],
        )
        encoded = json.dumps(
            result, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        self.assertLessEqual(
            len(encoded), case["oracle"]["failure_envelope_max_bytes"]
        )
        self.assertNotIn("observation", result)


class ReportAndSignatureBindingTests(unittest.TestCase):
    def test_zero_current_table_distinguishes_empty_from_all_removals(self):
        empty_case = _case(
            EXECUTION, "complete_empty_uses_only_catalogue_process"
        )
        empty_machine = _simulated_machine("post")
        empty_model = build_report_model(
            empty_machine, "fixture-a.example.com", report_width=120
        )
        self.assertEqual(
            empty_case["oracle"]["primary_table_kind"],
            empty_model["primary_table"]["kind"],
        )
        self.assertEqual([], empty_model["primary_table"]["rows"])
        empty_report = render_report(empty_model, report_width=120)
        self.assertIn("known_rows=0", empty_report)

        removed_case = _case(
            EXECUTION,
            "complete_all_removals_zero_current_still_reports_union_rows",
        )
        before_containers = {
            "fixture-a": _container("fixture-a", 1),
            "fixture-b": _container("fixture-b", 2),
        }
        before = _observation("obs-before-removals", containers=before_containers)
        after = _observation("obs-after-removals", containers={})
        run_window = compare_observations(before, after)
        machine = build_machine_result(
            {
                "operation": "post",
                "instance_id": "fixture-mdad",
                "correlation_id": None,
            },
            after,
            lifecycle={
                "record_id": "record-removals",
                "correlation_id": None,
                "between_observation_delta": run_window,
                "run_window_delta": run_window,
                "baseline": {
                    "advanced": True,
                    "before": before["observation_id"],
                    "after": after["observation_id"],
                },
                "journal_status": "complete",
                "persistence_outcome": "committed",
                "replay_outcome": None,
            },
        )
        model = build_report_model(
            machine, "fixture-a.example.com", report_width=120
        )
        self.assertEqual(
            removed_case["oracle"]["primary_table_kind"],
            model["primary_table"]["kind"],
        )
        self.assertEqual(
            removed_case["oracle"]["report_row_count"],
            len(model["primary_table"]["rows"]),
        )
        self.assertTrue(
            all(
                row["cells"]["after"] == removed_case["oracle"]["after_marker"]
                for row in model["primary_table"]["rows"]
            )
        )
        report = render_report(model, report_width=120)
        self.assertNotIn("known_rows=0", report)

    def test_phase_signature_known_answers_use_utf8_without_a_trailing_lf(self):
        for case_id in (
            "phase_signature_known_answer",
            "phase_signature_non_ascii_correlation_known_answer",
        ):
            with self.subTest(case=case_id):
                case = _case(EXECUTION, case_id)
                signature_object = case["input"]["signature_object"]
                encoded = json.dumps(
                    signature_object,
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
                self.assertEqual(
                    case["oracle"]["canonical_json_utf8"],
                    encoded.decode("utf-8"),
                )
                self.assertEqual(
                    case["oracle"]["exact_serialized_bytes"], len(encoded)
                )
                self.assertFalse(encoded.endswith(b"\n"))
                self.assertEqual(
                    case["oracle"]["exact_signature"],
                    phase_signature(
                        signature_object["operation"],
                        signature_object["instance_id"],
                        signature_object["scope"],
                        signature_object["correlation_id"],
                    ),
                )
                if "exact_utf8_hex" in case["oracle"]:
                    self.assertEqual(
                        case["oracle"]["exact_utf8_hex"], encoded.hex()
                    )


def _persistence_factory(state_root, instance_id):
    return PosixStateStore(
        state_root, instance_id, trusted_root_uid=os.stat("/").st_uid
    )


def _operation_inputs(state_root, operation, record_id=None):
    return {
        "enabled": True,
        "operation": operation,
        "instance_id": "fixture-mdad",
        "scope": ["fixture-*"],
        "record_id": record_id,
        "state_root": state_root,
        "report_mode": "none",
    }


def _execute_with_observation(inputs, observation, record_id):
    return execute_operation(
        inputs,
        discovery=lambda _scope_value, _timeout: copy.deepcopy(observation),
        persistence_factory=_persistence_factory,
        record_id_factory=lambda: record_id,
    )


class RetainedReplaySurfaceBindingTests(unittest.TestCase):
    def test_fixed_post_replay_is_byte_inode_write_and_action_stable(self):
        class CountingStore(PosixStateStore):
            transact_calls = 0

            def transact(self, *args, **kwargs):
                type(self).transact_calls += 1
                return PosixStateStore.transact(self, *args, **kwargs)

        def counting_factory(state_root, instance_id):
            return CountingStore(
                state_root,
                instance_id,
                trusted_root_uid=os.stat("/").st_uid,
            )

        with tempfile.TemporaryDirectory(
            prefix="docker-ansible-summary-replay-"
        ) as temporary:
            state_root = os.path.join(temporary, "state")
            record_id = "record-fixed-replay"
            pre_inputs = _operation_inputs(state_root, "pre")
            pre = execute_operation(
                pre_inputs,
                discovery=lambda _scope_value, _timeout: _observation(
                    "obs-fixed-pre"
                ),
                persistence_factory=counting_factory,
                record_id_factory=lambda: record_id,
            )
            post_inputs = _operation_inputs(
                state_root, "post", pre["record_id"]
            )
            execute_operation(
                post_inputs,
                discovery=lambda _scope_value, _timeout: _observation(
                    "obs-fixed-post"
                ),
                persistence_factory=counting_factory,
            )

            state_path = os.path.join(
                state_root, "fixture-mdad", "state.json"
            )
            before_bytes = Path(state_path).read_bytes()
            before_stat = os.stat(state_path)
            CountingStore.transact_calls = 0
            discovery_calls = []

            def forbidden_discovery(_scope_value, _timeout):
                discovery_calls.append(True)
                raise AssertionError("retained replay must not rediscover")

            replay = execute_operation(
                post_inputs,
                discovery=forbidden_discovery,
                persistence_factory=counting_factory,
            )
            after_stat = os.stat(state_path)
            self.assertEqual([], discovery_calls)
            self.assertEqual(0, CountingStore.transact_calls)
            self.assertEqual(before_bytes, Path(state_path).read_bytes())
            self.assertEqual(before_stat.st_ino, after_stat.st_ino)
            self.assertEqual(before_stat.st_mtime_ns, after_stat.st_mtime_ns)
            self.assertEqual("idempotent", replay["replay_outcome"])
            self.assertEqual("not_attempted", replay["persistence_outcome"])

            plugin, execute = _action_plugin(
                {
                    "enabled": True,
                    "operation": "post",
                    "instance_id": "fixture-mdad",
                    "scope": ["fixture-*"],
                    "record_id": record_id,
                    "state_root": state_root,
                    "report_mode": "none",
                },
                _module_success(replay),
            )
            action_result = _run_action(plugin)
            self.assertEqual(1, len(execute.calls))
            self.assertFalse(action_result["changed"])
            self.assertEqual("idempotent", action_result["replay_outcome"])
            self.assertEqual(before_bytes, Path(state_path).read_bytes())
            self.assertEqual(before_stat.st_ino, os.stat(state_path).st_ino)


class PostCommitPresentationFailureBindingTests(unittest.TestCase):
    def _prepare_prior_revision(
        self,
        state_root,
        prior_revision,
        latest_observation_id,
        open_record_id,
    ):
        for revision in range(1, prior_revision):
            observation_id = (
                latest_observation_id
                if revision == prior_revision - 1
                else "obs-seed-%02d" % revision
            )
            _execute_with_observation(
                _operation_inputs(state_root, "post"),
                _observation(observation_id),
                "record-seed-%02d" % revision,
            )
        _execute_with_observation(
            _operation_inputs(state_root, "pre", open_record_id),
            _observation(latest_observation_id),
            open_record_id,
        )
        store = _persistence_factory(
            state_root, "fixture-mdad"
        ).load(DEFAULT_STATE_MAX_BYTES, create_namespace=False)
        self.assertEqual(prior_revision, store["revision"])
        self.assertEqual(
            latest_observation_id,
            store["latest_complete_post"]["observation_id"],
        )
        return store

    def _exercise(self, case_id, injected_error):
        case = _case(PERSISTENCE, case_id)
        transition = case["transition"]
        oracle = case["oracle"]
        prior_revision = case["prior_state"]["revision"]
        latest_before = case["prior_state"]["latest_complete_post_id"]
        record_id = transition["record_id"]
        with tempfile.TemporaryDirectory(
            prefix="das-execution-binding-"
        ) as temporary:
            os.chmod(temporary, 0o700)
            state_root = os.path.join(temporary, "state")
            self._prepare_prior_revision(
                state_root,
                prior_revision,
                latest_before,
                record_id,
            )
            post_inputs = _operation_inputs(
                state_root, "post", record_id
            )
            machine = _execute_with_observation(
                post_inputs,
                _observation(transition["complete_observation_id"]),
                record_id,
            )
            self.assertEqual(
                oracle["persistence_outcome"],
                machine["persistence_outcome"],
            )

            plugin, execute = _action_plugin(
                {
                    "enabled": True,
                    "operation": "post",
                    "instance_id": "fixture-mdad",
                    "scope": ["fixture-*"],
                    "record_id": record_id,
                    "state_root": state_root,
                    "report_mode": "final",
                },
                _module_success(machine),
            )
            plugin._render = mock.Mock(side_effect=injected_error)
            result = _run_action(plugin, host=transition["host"])
            envelope = result["docker_ansible_summary_failure"]

            self.assertEqual(1, len(execute.calls))
            self.assertTrue(result["failed"])
            self.assertEqual(oracle["failure_reason"], envelope["failure_reason"])
            self.assertEqual(
                oracle["persistence_outcome"],
                envelope["persistence_outcome"],
            )
            self.assertTrue(envelope["committed_result_replayable"])
            expected_failure = (
                oracle["failure_envelope"]
                if "failure_envelope" in oracle
                else oracle["failure_diagnostic"]
            )
            self.assertEqual(
                expected_failure["replay_guidance"],
                envelope["replay_guidance"],
            )
            self.assertEqual(1, len(plugin._display.blocks))
            self.assertNotIn("DAS v1 |", plugin._display.blocks[0])

            store = _persistence_factory(
                state_root, "fixture-mdad"
            ).load(DEFAULT_STATE_MAX_BYTES, create_namespace=False)
            self.assertEqual(oracle["revision_after"], store["revision"])
            self.assertEqual(
                oracle["latest_complete_post_id"],
                store["latest_complete_post"]["observation_id"],
            )
            self.assertIn(
                record_id,
                [record["record_id"] for record in store["journal"]],
            )

            def discovery_must_not_run(_scope_value, _timeout):
                raise AssertionError("retained replay must not rediscover")

            replay_inputs = dict(post_inputs)
            replay_inputs["report_mode"] = "none"
            replay = execute_operation(
                replay_inputs,
                discovery=discovery_must_not_run,
                persistence_factory=_persistence_factory,
            )
            self.assertEqual("idempotent", replay["replay_outcome"])
            self.assertEqual("not_attempted", replay["persistence_outcome"])
            replayed_store = _persistence_factory(
                state_root, "fixture-mdad"
            ).load(DEFAULT_STATE_MAX_BYTES, create_namespace=False)
            self.assertEqual(store, replayed_store)

    def test_render_failure_after_real_commit_is_bounded_and_replayable(self):
        self._exercise(
            "render_failure_after_commit",
            RuntimeError("synthetic renderer failure"),
        )

    def test_capacity_failure_after_real_commit_is_bounded_and_replayable(self):
        self._exercise(
            "presentation_capacity_failure_after_commit",
            ACTION_PLUGIN.PresentationCapacityError(
                "synthetic presentation capacity failure"
            ),
        )


if __name__ == "__main__":
    unittest.main()
