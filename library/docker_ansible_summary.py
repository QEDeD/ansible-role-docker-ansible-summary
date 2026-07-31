#!/usr/bin/python
# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Ansible managed-host module for Docker Ansible Summary."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: docker_ansible_summary
short_description: Observe and compare bounded Docker container state
version_added: "1.0.0"
description:
  - Implements the managed-host half of Docker Ansible Summary.
  - Use through the role's action plugin and C(tasks/observe.yml).
options:
  enabled:
    description: Whether the observer is enabled.
    type: raw
    required: true
  operation:
    description: Observation lifecycle operation.
    type: raw
  instance_id:
    description: Stable state-isolation label.
    type: raw
  scope:
    description: Explicit container-name pattern or pattern list.
    type: raw
  record_id:
    description: Optional caller or prior pre-operation record identifier.
    type: raw
  state_root:
    description: Absolute POSIX root for bounded instance state.
    type: raw
  journal_max_records:
    description: Maximum retained journal records.
    type: raw
  state_max_bytes:
    description: Maximum canonical state bytes.
    type: raw
  correlation_id:
    description: Optional non-secret caller correlation value.
    type: raw
  report_mode:
    description: Controller presentation mode.
    type: raw
  report_width:
    description: Controller report width.
    type: raw
  discovery_timeout_seconds:
    description: One overall Docker discovery deadline.
    type: raw
  failure_policy:
    description: Handling of partial or unavailable observations.
    type: raw
supports_check_mode: true
author:
  - QEDeD
"""

EXAMPLES = r"""
- name: Observe current Docker state through the supported role entry point
  ansible.builtin.import_role:
    name: docker_ansible_summary
    tasks_from: observe
    allow_duplicates: true
  vars:
    docker_ansible_summary_operation: status
    docker_ansible_summary_instance_id: example
    docker_ansible_summary_scope: "example-*"
"""

RETURN = r"""
schema_version:
  description: DAS machine-result schema version.
  returned: success
  type: int
observation:
  description: Strict allowlisted current or retained observation.
  returned: success
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule

try:
    from ansible.module_utils.docker_ansible_summary.engine import (
        OperationFailure,
        execute_operation,
    )
    from ansible.module_utils.docker_ansible_summary.discovery import discover
    from ansible.module_utils.docker_ansible_summary.validation import (
        ValidationError,
    )
except ImportError:
    from module_utils.docker_ansible_summary.engine import (
        OperationFailure,
        execute_operation,
    )
    from module_utils.docker_ansible_summary.discovery import discover
    from module_utils.docker_ansible_summary.validation import ValidationError


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
        # The public contract has no exception-text channel. This last-resort
        # boundary prevents traceback, process data, or module arguments from
        # reaching a normal callback if an implementation defect escapes the
        # modeled paths.
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
    # Keep the complete machine result private until the controller action
    # validates and exposes it. In particular, top-level ``warnings`` has
    # framework semantics inside AnsibleModule.exit_json and cannot safely be
    # transported as a public DAS field at this boundary.
    module.exit_json(changed=False, _das_machine_result=result)


if __name__ == "__main__":
    main()
