# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Controller-side validation, sanitization, rendering, and failure policy."""

from __future__ import absolute_import, division, print_function

import importlib
import importlib.util
import os
import sys

from ansible.plugins.action import ActionBase


def _load_role_module_utils():
    """Load this role's pure package under a collision-resistant alias."""

    package_name = "_docker_ansible_summary_role_utils"
    if package_name in sys.modules:
        return package_name
    package_directory = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "module_utils",
        "docker_ansible_summary",
    )
    specification = importlib.util.spec_from_file_location(
        package_name,
        os.path.join(package_directory, "__init__.py"),
        submodule_search_locations=[package_directory],
    )
    if specification is None or specification.loader is None:
        raise ImportError("DAS role module_utils package is unavailable")
    package = importlib.util.module_from_spec(specification)
    sys.modules[package_name] = package
    specification.loader.exec_module(package)
    return package_name

try:
    from ansible.module_utils.docker_ansible_summary.action_support import (
        compact_warning_block,
        detect_public_variable_error,
        effective_diagnostic_width,
        failure_block,
        input_error_block,
        presentation_kind,
    )
    from ansible.module_utils.docker_ansible_summary.model import (
        ModelError,
        PresentationCapacityError,
    )
    from ansible.module_utils.docker_ansible_summary.render import render_report
    from ansible.module_utils.docker_ansible_summary.report import (
        build_report_model,
    )
    from ansible.module_utils.docker_ansible_summary.result import (
        ResultContractError,
        disabled_machine_result,
        failure_result,
        sanitize_private_failure,
        sanitize_machine_result,
    )
    from ansible.module_utils.docker_ansible_summary.validation import (
        ValidationError,
        validate_public_inputs,
    )
except ImportError:
    _ROLE_PACKAGE = _load_role_module_utils()
    _action_support = importlib.import_module(
        _ROLE_PACKAGE + ".action_support"
    )
    _model = importlib.import_module(_ROLE_PACKAGE + ".model")
    _render = importlib.import_module(_ROLE_PACKAGE + ".render")
    _report = importlib.import_module(_ROLE_PACKAGE + ".report")
    _result = importlib.import_module(_ROLE_PACKAGE + ".result")
    _validation = importlib.import_module(_ROLE_PACKAGE + ".validation")

    compact_warning_block = _action_support.compact_warning_block
    detect_public_variable_error = (
        _action_support.detect_public_variable_error
    )
    effective_diagnostic_width = (
        _action_support.effective_diagnostic_width
    )
    failure_block = _action_support.failure_block
    input_error_block = _action_support.input_error_block
    presentation_kind = _action_support.presentation_kind
    ModelError = _model.ModelError
    PresentationCapacityError = _model.PresentationCapacityError
    render_report = _render.render_report
    build_report_model = _report.build_report_model
    ResultContractError = _result.ResultContractError
    disabled_machine_result = _result.disabled_machine_result
    failure_result = _result.failure_result
    sanitize_private_failure = _result.sanitize_private_failure
    sanitize_machine_result = _result.sanitize_machine_result
    ValidationError = _validation.ValidationError
    validate_public_inputs = _validation.validate_public_inputs


class ActionModule(ActionBase):
    """Implement the single DAS role task."""

    TRANSFERS_FILES = False

    def _display_block(self, block):
        if not block:
            return True
        try:
            self._display.display(block)
            return True
        except Exception:
            return False

    def _input_failure(self, host, error, arguments):
        width = effective_diagnostic_width(arguments)
        self._display_block(input_error_block(error, width))
        return failure_result(
            host,
            "invalid_input",
            persistence_outcome="not_attempted",
        )

    def _hard_failure(self, host, inputs, private):
        reason = private.get("failure_reason")
        width = inputs["report_width"]
        result = failure_result(
            host,
            reason,
            instance_id=inputs["instance_id"],
            operation=inputs["operation"],
            record_id=private.get("record_id"),
            observation_status=private.get("observation_status"),
            observation_reason=private.get("observation_reason"),
            persistence_outcome=private.get(
                "persistence_outcome", "failed"
            ),
            committed_result_replayable=private.get(
                "committed_result_replayable", False
            ),
            retry_unchanged_phase=private.get(
                "retry_unchanged_phase", False
            ),
        )
        envelope = result["docker_ansible_summary_failure"]
        self._display_block(
            failure_block(
                host,
                reason,
                instance_id=inputs["instance_id"],
                operation=inputs["operation"],
                report_width=width,
                record_id=envelope["record_id"],
                persistence_outcome=envelope["persistence_outcome"],
                replay_guidance=envelope["replay_guidance"],
            )
        )
        return result

    @staticmethod
    def _retained_result_is_replayable(machine):
        return bool(
            machine.get("record_id")
            and machine.get("operation") in ("pre", "post")
            and not machine.get("simulated")
            and (
                machine.get("persistence_outcome") == "committed"
                or machine.get("replay_outcome") == "idempotent"
            )
        )

    def _presentation_failure(self, host, inputs, machine, reason):
        replayable = self._retained_result_is_replayable(machine)
        result = failure_result(
            host,
            reason,
            instance_id=machine.get("instance_id"),
            operation=machine.get("operation"),
            record_id=machine.get("record_id"),
            observation_status=machine.get("observation_status"),
            observation_reason=(
                None
                if machine.get("observation") is None
                else machine["observation"].get("reason_code")
            ),
            persistence_outcome=machine.get("persistence_outcome"),
            committed_result_replayable=replayable,
        )
        envelope = result["docker_ansible_summary_failure"]
        self._display_block(
            failure_block(
                host,
                reason,
                instance_id=machine.get("instance_id"),
                operation=machine.get("operation"),
                report_width=inputs["report_width"],
                record_id=envelope["record_id"],
                persistence_outcome=envelope["persistence_outcome"],
                replay_guidance=envelope["replay_guidance"],
            )
        )
        return result

    def _render(self, host, inputs, machine):
        kind = presentation_kind(machine, inputs["report_mode"])
        if kind == "none":
            return None
        if kind == "warning":
            return compact_warning_block(
                machine,
                host,
                inputs["report_mode"],
                inputs["report_width"],
            )
        model = build_report_model(
            machine,
            host,
            report_width=inputs["report_width"],
        )
        return render_report(
            model,
            report_width=inputs["report_width"],
        )

    def run(self, tmp=None, task_vars=None):
        task_vars = task_vars or {}
        super(ActionModule, self).run(tmp, task_vars)
        arguments = dict(self._task.args)
        host = str(task_vars.get("inventory_hostname", "<unknown>"))

        enabled = arguments.get("enabled", True)
        if not isinstance(enabled, bool):
            return self._input_failure(
                host,
                ValidationError("invalid_type", "enabled"),
                arguments,
            )
        if not enabled:
            result = disabled_machine_result()
            result["changed"] = False
            return result

        namespace_error = detect_public_variable_error(
            arguments, task_vars
        )
        if namespace_error is not None:
            return self._input_failure(host, namespace_error, arguments)

        check_mode = bool(
            getattr(self._task, "check_mode", False)
            or task_vars.get("ansible_check_mode", False)
            or getattr(self._play_context, "check_mode", False)
        )
        try:
            inputs = validate_public_inputs(
                arguments,
                check_mode=check_mode,
            )
        except ValidationError as error:
            return self._input_failure(host, error, arguments)

        module_result = self._execute_module(
            module_name="docker_ansible_summary",
            module_args=arguments,
            task_vars=task_vars,
            tmp=tmp,
        )
        if not isinstance(module_result, dict):
            machine = {
                "operation": inputs["operation"],
                "instance_id": inputs["instance_id"],
                "record_id": None,
                "observation": None,
                "observation_status": None,
                "persistence_outcome": "failed",
                "replay_outcome": None,
                "simulated": check_mode,
            }
            return self._presentation_failure(
                host, inputs, machine, "render_failed"
            )
        private_failure = module_result.get("_das_failure")
        if module_result.get("failed") or private_failure is not None:
            try:
                private_failure = sanitize_private_failure(private_failure)
                return self._hard_failure(host, inputs, private_failure)
            except ResultContractError:
                return self._hard_failure(
                    host,
                    inputs,
                    {
                        "failure_reason": "state_write_failed",
                        "persistence_outcome": "failed",
                        "record_id": None,
                        "observation_status": None,
                        "observation_reason": None,
                        "committed_result_replayable": False,
                        "retry_unchanged_phase": False,
                    },
                )

        try:
            machine = sanitize_machine_result(
                module_result.get("_das_machine_result"),
                expected_inputs=inputs,
                check_mode=check_mode,
            )
        except (ModelError, ResultContractError):
            machine = {
                "operation": inputs["operation"],
                "instance_id": inputs["instance_id"],
                "record_id": None,
                "observation": None,
                "observation_status": None,
                "persistence_outcome": "failed",
                "replay_outcome": None,
                "simulated": check_mode,
            }
            return self._presentation_failure(
                host, inputs, machine, "render_failed"
            )

        try:
            block = self._render(host, inputs, machine)
        except PresentationCapacityError:
            return self._presentation_failure(
                host,
                inputs,
                machine,
                "presentation_capacity_exceeded",
            )
        except Exception:
            return self._presentation_failure(
                host, inputs, machine, "render_failed"
            )
        if not self._display_block(block):
            return self._presentation_failure(
                host, inputs, machine, "render_failed"
            )

        observation = machine.get("observation")
        if (
            inputs["failure_policy"] == "fail_after_report"
            and observation is not None
            and observation.get("status") != "complete"
        ):
            return failure_result(
                host,
                "observation_noncomplete",
                instance_id=machine["instance_id"],
                operation=machine["operation"],
                record_id=machine["record_id"],
                observation_status=machine["observation_status"],
                observation_reason=observation.get("reason_code"),
                persistence_outcome=machine["persistence_outcome"],
                committed_result_replayable=(
                    self._retained_result_is_replayable(machine)
                ),
            )

        result = dict(machine)
        result["changed"] = False
        return result
