#!/usr/bin/python
# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Harness-only module shadow using the production persistence fault seam."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.docker_ansible_summary.discovery import discover
from ansible.module_utils.docker_ansible_summary.engine import (
    OperationFailure,
    execute_operation,
)
from ansible.module_utils.docker_ansible_summary.persistence import (
    PosixStateStore,
)
from ansible.module_utils.docker_ansible_summary.validation import (
    ValidationError,
)


ARGUMENT_NAMES = (
    "enabled",
    "operation",
    "instance_id",
    "scope",
    "record_id",
    "state_root",
    "journal_max_records",
    "state_max_bytes",
    "correlation_id",
    "report_mode",
    "report_width",
    "discovery_timeout_seconds",
    "failure_policy",
)
FAULT_STAGES = frozenset(
    (
        "before_atomic_replace",
        "after_atomic_replace_before_directory_fsync",
    )
)


def _argument_spec():
    return {
        name: {"type": "raw", "required": name == "enabled"}
        for name in ARGUMENT_NAMES
    }


def _validation_failure():
    return {
        "failure_reason": "invalid_input",
        "persistence_outcome": "not_attempted",
        "record_id": None,
        "observation_status": None,
        "observation_reason": None,
        "committed_result_replayable": False,
        "retry_unchanged_phase": False,
    }


def _persistence_factory(state_root, instance_id):
    selected = os.environ.get("DAS_CALLBACK_FAILURE_INJECTION")

    def inject(stage):
        if selected in FAULT_STAGES and stage == selected:
            raise RuntimeError("harness-only persistence fault")

    return PosixStateStore(
        state_root,
        instance_id,
        fault_injector=inject,
    )


def main():
    module = AnsibleModule(
        argument_spec=_argument_spec(),
        supports_check_mode=True,
    )

    def module_discovery(scope, timeout_seconds):
        docker_path = module.get_bin_path("docker", required=False)
        return discover(
            scope,
            timeout_seconds,
            docker_path=docker_path,
        )

    try:
        result = execute_operation(
            module.params,
            check_mode=module.check_mode,
            discovery=module_discovery,
            persistence_factory=_persistence_factory,
        )
    except ValidationError:
        module.exit_json(
            changed=False,
            failed=True,
            _das_failure=_validation_failure(),
        )
    except OperationFailure as error:
        module.exit_json(
            changed=False,
            failed=True,
            _das_failure=error.as_private_dict(),
        )
    except Exception:
        module.exit_json(
            changed=False,
            failed=True,
            _das_failure={
                "failure_reason": "state_write_failed",
                "persistence_outcome": "failed",
                "record_id": None,
                "observation_status": None,
                "observation_reason": None,
                "committed_result_replayable": False,
                "retry_unchanged_phase": False,
            },
        )
    module.exit_json(changed=False, _das_machine_result=result)


if __name__ == "__main__":
    main()
