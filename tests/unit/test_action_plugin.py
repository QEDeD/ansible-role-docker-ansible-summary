# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import absolute_import, division, print_function

import importlib.util
import json
import os
import sys
import types
import unittest
from unittest import mock

from module_utils.docker_ansible_summary.compare import compare_observations
from module_utils.docker_ansible_summary.result import (
    FAILURE_FIELDS,
    MACHINE_RESULT_FIELDS,
    RETRY_WITHOUT_REPORT,
    RETRY_WITH_REPORT,
    build_machine_result,
)
from module_utils.docker_ansible_summary.validation import normalize_scope


ROLE_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
PLUGIN_PATH = os.path.join(
    ROLE_ROOT, "action_plugins", "docker_ansible_summary.py"
)
SPECIFICATION = importlib.util.spec_from_file_location(
    "das_action_plugin_under_test", PLUGIN_PATH
)
ACTION_PLUGIN = importlib.util.module_from_spec(SPECIFICATION)


class _ActionBaseStub(object):
    """Enough ActionBase surface to load and invoke the plugin without Ansible."""

    def run(self, tmp=None, task_vars=None):
        return {}


_ANSIBLE_STUB = types.ModuleType("ansible")
_ANSIBLE_STUB.__path__ = []
_PLUGINS_STUB = types.ModuleType("ansible.plugins")
_PLUGINS_STUB.__path__ = []
_ACTION_STUB = types.ModuleType("ansible.plugins.action")
_ACTION_STUB.ActionBase = _ActionBaseStub
with mock.patch.dict(
    sys.modules,
    {
        "ansible": _ANSIBLE_STUB,
        "ansible.plugins": _PLUGINS_STUB,
        "ansible.plugins.action": _ACTION_STUB,
    },
):
    SPECIFICATION.loader.exec_module(ACTION_PLUGIN)


class _Task(object):
    action = "docker_ansible_summary"
    async_val = 0

    def __init__(self, arguments=None, check_mode=False):
        self.args = dict(
            arguments
            or {
                "enabled": True,
                "operation": "status",
                "instance_id": "unit-fixture",
                "scope": "*",
                "report_mode": "none",
            }
        )
        self.check_mode = check_mode


class _PlayContext(object):
    check_mode = False


class _Display(object):
    def __init__(self):
        self.blocks = []

    def display(self, block):
        self.blocks.append(block)


class _ExecuteProbe(object):
    def __init__(self, result, events=None):
        self.result = result
        self.calls = []
        self.events = events

    def __call__(self, **kwargs):
        if self.events is not None:
            self.events.append("module")
        self.calls.append(kwargs)
        return self.result


class _FailingDisplay(object):
    def __init__(self):
        self.attempts = []

    def display(self, block):
        self.attempts.append(block)
        raise RuntimeError("synthetic display failure")


def _scope():
    return normalize_scope("*")


def _observation(status="complete"):
    reason = None if status == "complete" else "docker_unavailable"
    return {
        "observation_id": "obs-action-plugin",
        "observed_at": "2026-07-30T12:00:00Z",
        "scope": _scope(),
        "status": status,
        "reason_code": reason,
        "warnings": (
            [] if reason is None else ["Docker daemon was unavailable"]
        ),
        "discovery_backend": "docker_cli_v1",
        "metadata_gaps": [] if status == "complete" else ["docker.catalogue"],
        "containers": {} if status != "unavailable" else None,
    }


def _status_machine(status="complete"):
    return build_machine_result(
        {
            "operation": "status",
            "instance_id": "unit-fixture",
            "correlation_id": None,
        },
        _observation(status),
    )


def _committed_pre_machine(status="complete"):
    observation = _observation(status)
    baseline_delta = compare_observations(None, observation)
    return build_machine_result(
        {
            "operation": "pre",
            "instance_id": "unit-fixture",
            "correlation_id": None,
        },
        observation,
        lifecycle={
            "record_id": "record-action-plugin",
            "correlation_id": None,
            "between_observation_delta": baseline_delta,
            "run_window_delta": None,
            "baseline": {
                "advanced": False,
                "before": None,
                "after": None,
            },
            "journal_status": "open",
            "persistence_outcome": "committed",
            "replay_outcome": None,
        },
    )


def _plugin(
    arguments,
    module_result,
    display=None,
    events=None,
    check_mode=False,
):
    plugin = object.__new__(ACTION_PLUGIN.ActionModule)
    plugin._task = _Task(arguments, check_mode=check_mode)
    plugin._play_context = _PlayContext()
    plugin._display = display or _Display()
    execute = _ExecuteProbe(module_result, events=events)
    plugin._execute_module = execute
    return plugin, execute


def _run(plugin):
    with mock.patch.object(ACTION_PLUGIN.ActionBase, "run", return_value={}):
        return plugin.run(task_vars={"inventory_hostname": "fixture.example"})


class ActionPluginBoundaryTests(unittest.TestCase):
    def test_disabled_short_circuit_has_zero_module_and_display_calls(self):
        plugin, execute = _plugin(
            {"enabled": False},
            AssertionError("disabled action must not invoke the module"),
        )

        result = _run(plugin)

        self.assertEqual([], execute.calls)
        self.assertEqual([], plugin._display.blocks)
        self.assertEqual(
            set(MACHINE_RESULT_FIELDS) | {"changed"},
            set(result),
        )
        self.assertFalse(result["changed"])
        self.assertTrue(result["skipped"])

    def test_valid_success_has_exact_public_allowlist_and_mode_counts(self):
        cases = (
            ("final", 1),
            ("each", 1),
            ("none", 0),
        )
        for report_mode, expected_display_calls in cases:
            with self.subTest(report_mode=report_mode):
                arguments = {
                    "enabled": True,
                    "operation": "status",
                    "instance_id": "unit-fixture",
                    "scope": "*",
                    "report_mode": report_mode,
                }
                module_result = {
                    "changed": False,
                    "_das_machine_result": _status_machine(),
                    "invocation": {"module_args": {"canary": "private"}},
                    "stdout": "private",
                }
                plugin, execute = _plugin(arguments, module_result)

                result = _run(plugin)

                self.assertEqual(1, len(execute.calls))
                self.assertEqual(
                    expected_display_calls, len(plugin._display.blocks)
                )
                self.assertEqual(
                    set(MACHINE_RESULT_FIELDS) | {"changed"},
                    set(result),
                )
                self.assertFalse(result["changed"])
                self.assertNotIn("canary", json.dumps(result))
                self.assertNotIn("_das_machine_result", result)
                self.assertEqual(
                    "docker_ansible_summary",
                    execute.calls[0]["module_name"],
                )

    def test_per_task_check_mode_binds_simulated_result(self):
        machine = build_machine_result(
            {
                "operation": "pre",
                "instance_id": "unit-fixture",
                "correlation_id": None,
            },
            _observation(),
            simulated=True,
        )
        plugin, execute = _plugin(
            {
                "enabled": True,
                "operation": "pre",
                "instance_id": "unit-fixture",
                "scope": "*",
                "report_mode": "none",
            },
            {"changed": False, "_das_machine_result": machine},
            check_mode=True,
        )

        result = _run(plugin)

        self.assertEqual(1, len(execute.calls))
        self.assertTrue(result["simulated"])
        self.assertIsNone(result["record_id"])

    def test_valid_private_failure_returns_only_bounded_public_envelope(self):
        private = {
            "failure_reason": "revision_conflict",
            "persistence_outcome": "conflict",
            "record_id": "record-action-plugin",
            "observation_status": "complete",
            "observation_reason": None,
            "committed_result_replayable": False,
            "retry_unchanged_phase": False,
        }
        plugin, execute = _plugin(
            {
                "enabled": True,
                "operation": "post",
                "instance_id": "unit-fixture",
                "scope": "*",
                "record_id": "record-action-plugin",
                "report_mode": "none",
            },
            {
                "changed": False,
                "failed": True,
                "_das_failure": private,
                "stderr": "private-canary",
                "invocation": {"module_args": {"private": "canary"}},
            },
        )

        result = _run(plugin)

        self.assertEqual(1, len(execute.calls))
        self.assertEqual(1, len(plugin._display.blocks))
        self.assertEqual(
            {"changed", "failed", "docker_ansible_summary_failure"},
            set(result),
        )
        envelope = result["docker_ansible_summary_failure"]
        self.assertEqual(set(FAILURE_FIELDS), set(envelope))
        self.assertEqual("revision_conflict", envelope["failure_reason"])
        self.assertEqual("conflict", envelope["persistence_outcome"])
        self.assertNotIn("private-canary", json.dumps(result))
        compact = json.dumps(
            result,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.assertLessEqual(len(compact), 1024)

    def test_render_failures_after_commit_are_replayable_and_bounded(self):
        cases = (
            (RuntimeError("synthetic renderer failure"), "render_failed"),
            (
                ACTION_PLUGIN.PresentationCapacityError(
                    "synthetic capacity failure"
                ),
                "presentation_capacity_exceeded",
            ),
        )
        for error, expected_reason in cases:
            with self.subTest(expected_reason=expected_reason):
                plugin, execute = _plugin(
                    {
                        "enabled": True,
                        "operation": "pre",
                        "instance_id": "unit-fixture",
                        "scope": "*",
                        "record_id": "record-action-plugin",
                        "report_mode": "each",
                    },
                    {
                        "changed": False,
                        "_das_machine_result": _committed_pre_machine(),
                    },
                )
                plugin._render = mock.Mock(side_effect=error)

                result = _run(plugin)

                self.assertEqual(1, len(execute.calls))
                self.assertEqual(1, plugin._render.call_count)
                self.assertEqual(1, len(plugin._display.blocks))
                envelope = result["docker_ansible_summary_failure"]
                self.assertEqual(expected_reason, envelope["failure_reason"])
                self.assertEqual("committed", envelope["persistence_outcome"])
                self.assertTrue(envelope["committed_result_replayable"])
                self.assertEqual(
                    RETRY_WITHOUT_REPORT, envelope["replay_guidance"]
                )
                self.assertEqual(
                    {"changed", "failed", "docker_ansible_summary_failure"},
                    set(result),
                )

    def test_display_failure_after_commit_returns_replayable_render_failure(self):
        display = _FailingDisplay()
        plugin, execute = _plugin(
            {
                "enabled": True,
                "operation": "pre",
                "instance_id": "unit-fixture",
                "scope": "*",
                "record_id": "record-action-plugin",
                "report_mode": "each",
            },
            {
                "changed": False,
                "_das_machine_result": _committed_pre_machine(),
            },
            display=display,
        )
        plugin._render = mock.Mock(return_value="synthetic successful report")

        result = _run(plugin)

        self.assertEqual(1, len(execute.calls))
        self.assertEqual(1, plugin._render.call_count)
        # The first attempt is the report; the second is the bounded failure
        # diagnostic, which the same broken display transport also rejects.
        self.assertEqual(2, len(display.attempts))
        self.assertEqual("synthetic successful report", display.attempts[0])
        envelope = result["docker_ansible_summary_failure"]
        self.assertEqual("render_failed", envelope["failure_reason"])
        self.assertEqual("committed", envelope["persistence_outcome"])
        self.assertTrue(envelope["committed_result_replayable"])
        self.assertEqual(RETRY_WITHOUT_REPORT, envelope["replay_guidance"])

    def test_fail_after_report_orders_module_render_display_then_failure(self):
        events = []
        display = _Display()
        original_display = display.display

        def observed_display(block):
            events.append("display")
            original_display(block)

        display.display = observed_display
        plugin, execute = _plugin(
            {
                "enabled": True,
                "operation": "pre",
                "instance_id": "unit-fixture",
                "scope": "*",
                "record_id": "record-action-plugin",
                "report_mode": "final",
                "failure_policy": "fail_after_report",
            },
            {
                "changed": False,
                "_das_machine_result": _committed_pre_machine(
                    status="unavailable"
                ),
            },
            display=display,
            events=events,
        )
        original_render = plugin._render

        def observed_render(host, inputs, machine):
            events.append("render")
            return original_render(host, inputs, machine)

        plugin._render = observed_render

        result = _run(plugin)

        self.assertEqual(["module", "render", "display"], events)
        self.assertEqual(1, len(execute.calls))
        self.assertEqual(1, len(display.blocks))
        self.assertIn("DAS warning", display.blocks[0])
        envelope = result["docker_ansible_summary_failure"]
        self.assertEqual(
            "observation_noncomplete", envelope["failure_reason"]
        )
        self.assertEqual("docker_unavailable", envelope["observation_reason"])
        self.assertEqual("committed", envelope["persistence_outcome"])
        self.assertTrue(envelope["committed_result_replayable"])
        self.assertEqual(RETRY_WITH_REPORT, envelope["replay_guidance"])

    def test_nonmapping_module_result_fails_closed_once(self):
        plugin, execute = _plugin(
            _Task().args,
            ["not", "a", "mapping"],
        )

        result = _run(plugin)

        self.assertEqual(1, len(execute.calls))
        self.assertEqual(1, len(plugin._display.blocks))
        self.assertEqual(
            {"changed", "failed", "docker_ansible_summary_failure"},
            set(result),
        )
        self.assertEqual(
            "render_failed",
            result["docker_ansible_summary_failure"]["failure_reason"],
        )


if __name__ == "__main__":
    unittest.main()
