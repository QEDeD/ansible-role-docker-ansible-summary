# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Harness-only spy that delegates to the production DAS action plugin."""

from __future__ import absolute_import, division, print_function

import importlib.util
import json
import os
import stat


_MAX_RECORD_BYTES = 512
_MAX_TEXT_LENGTH = 128


def _required_environment(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError("DAS action-spy environment is incomplete")
    return value


def _load_production_action():
    source = _required_environment("DAS_ACTION_SPY_REAL_PLUGIN")
    specification = importlib.util.spec_from_file_location(
        "_docker_ansible_summary_production_action",
        source,
    )
    if specification is None or specification.loader is None:
        raise ImportError("production DAS action plugin is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module.ActionModule


_ProductionActionModule = _load_production_action()


def _bounded_text(value):
    text = str(value)
    if len(text) > _MAX_TEXT_LENGTH:
        raise RuntimeError("DAS action-spy value exceeds its bound")
    return text


def _append_record(record):
    log_path = _required_environment("DAS_ACTION_SPY_LOG")
    payload = (
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if len(payload) > _MAX_RECORD_BYTES:
        raise RuntimeError("DAS action-spy record exceeds its bound")

    flags = os.O_WRONLY | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(log_path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("DAS action-spy log is not a regular file")
        if metadata.st_uid != os.geteuid():
            raise RuntimeError("DAS action-spy log has an unexpected owner")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise RuntimeError("DAS action-spy log has an unsafe mode")
        if os.write(descriptor, payload) != len(payload):
            raise RuntimeError("DAS action-spy record write was incomplete")
    finally:
        os.close(descriptor)


class ActionModule(_ProductionActionModule):
    """Record each real module boundary crossing, then delegate unchanged."""

    def _execute_module(self, *args, **kwargs):
        module_args = kwargs.get("module_args") or {}
        task_vars = kwargs.get("task_vars") or {}
        _append_record(
            {
                "host": _bounded_text(
                    task_vars.get("inventory_hostname", "<unknown>")
                ),
                "module_name": _bounded_text(
                    kwargs.get("module_name", "<unknown>")
                ),
                "operation": _bounded_text(
                    module_args.get("operation", "<omitted>")
                ),
                "schema_version": 1,
            }
        )
        return super(ActionModule, self)._execute_module(*args, **kwargs)
