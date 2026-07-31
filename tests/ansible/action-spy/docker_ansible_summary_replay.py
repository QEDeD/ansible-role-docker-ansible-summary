# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Harness-only replay spy that brackets the real module invocation."""

from __future__ import absolute_import, division, print_function

import hashlib
import importlib.util
import json
import os
import stat


_MAX_LOG_BYTES = 32768
_MAX_RECORD_BYTES = 4096
_MAX_STATE_BYTES = 1048576
_MAX_TEXT_LENGTH = 128


def _required_environment(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError("DAS replay-spy environment is incomplete")
    return value


def _load_production_action():
    source = _required_environment("DAS_REPLAY_REAL_PLUGIN")
    specification = importlib.util.spec_from_file_location(
        "_docker_ansible_summary_replay_production_action",
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
        raise RuntimeError("DAS replay-spy value exceeds its bound")
    return text


def _metadata(path, expected_kind):
    try:
        metadata = os.lstat(path)
    except OSError:
        return {"exists": False}
    if expected_kind == "regular" and not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError("DAS replay-spy expected a regular file")
    if expected_kind == "directory" and not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError("DAS replay-spy expected a directory")
    return {
        "ctime_ns": metadata.st_ctime_ns,
        "exists": True,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "mtime_ns": metadata.st_mtime_ns,
        "size": metadata.st_size,
    }


def _read_bounded(path, maximum):
    with open(path, "rb") as source:
        payload = source.read(maximum + 1)
    if len(payload) > maximum:
        raise RuntimeError("DAS replay-spy evidence exceeds its bound")
    return payload


def _state_snapshot(state_root, instance_id):
    instance_path = os.path.join(state_root, instance_id)
    state_path = os.path.join(instance_path, "state.json")
    lock_path = os.path.join(instance_path, "state.lock")
    state_metadata = _metadata(state_path, "regular")
    state_bytes = None
    if state_metadata["exists"]:
        state_bytes = _read_bounded(state_path, _MAX_STATE_BYTES)
        try:
            store = json.loads(state_bytes.decode("utf-8"))
            canonical = (
                json.dumps(
                    store,
                    allow_nan=False,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
                + b"\n"
            )
        except (TypeError, ValueError, UnicodeError):
            raise RuntimeError("DAS replay-spy state is not canonical JSON")
        state_metadata.update(
            {
                "canonical": canonical == state_bytes,
                "revision": store.get("revision"),
                "sha256": hashlib.sha256(state_bytes).hexdigest(),
            }
        )
    return {
        "directory": _metadata(instance_path, "directory"),
        "lock": _metadata(lock_path, "regular"),
        "state": state_metadata,
    }, state_bytes


def _docker_snapshot():
    log_path = _required_environment("DAS_REPLAY_DOCKER_LOG")
    payload = _read_bounded(log_path, _MAX_LOG_BYTES)
    return {
        "lines": len(payload.splitlines()),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }, payload


def _append_record(record):
    log_path = _required_environment("DAS_REPLAY_SPY_LOG")
    payload = (
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if len(payload) > _MAX_RECORD_BYTES:
        raise RuntimeError("DAS replay-spy record exceeds its bound")

    flags = os.O_WRONLY | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(log_path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("DAS replay-spy log is not a regular file")
        if metadata.st_uid != os.geteuid():
            raise RuntimeError("DAS replay-spy log has an unexpected owner")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise RuntimeError("DAS replay-spy log has an unsafe mode")
        if os.write(descriptor, payload) != len(payload):
            raise RuntimeError("DAS replay-spy record write was incomplete")
    finally:
        os.close(descriptor)


def _signature_inputs(module_args):
    value = {
        "correlation_id": module_args.get("correlation_id"),
        "instance_id": _bounded_text(
            module_args.get("instance_id", "<omitted>")
        ),
        "operation": _bounded_text(
            module_args.get("operation", "<omitted>")
        ),
        "scope": module_args.get("scope"),
    }
    try:
        payload = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise RuntimeError("DAS replay-spy signature inputs are invalid")
    if len(payload) > _MAX_RECORD_BYTES // 4:
        raise RuntimeError("DAS replay-spy signature inputs exceed their bound")
    return value, hashlib.sha256(payload).hexdigest()


class ActionModule(_ProductionActionModule):
    """Snapshot persistence and Docker evidence around the real module."""

    def _execute_module(self, *args, **kwargs):
        module_args = kwargs.get("module_args") or {}
        task_vars = kwargs.get("task_vars") or {}
        state_root = _bounded_text(module_args.get("state_root", "<omitted>"))
        expected_root = os.path.abspath(
            _required_environment("DAS_REPLAY_STATE_ROOT")
        )
        if os.path.abspath(state_root) != expected_root:
            raise RuntimeError("DAS replay-spy state root differs")
        instance_id = _bounded_text(
            module_args.get("instance_id", "<omitted>")
        )

        state_before, state_bytes_before = _state_snapshot(
            state_root, instance_id
        )
        docker_before, docker_bytes_before = _docker_snapshot()
        result = super(ActionModule, self)._execute_module(*args, **kwargs)
        state_after, state_bytes_after = _state_snapshot(
            state_root, instance_id
        )
        docker_after, docker_bytes_after = _docker_snapshot()

        record_id = module_args.get("record_id")
        signature_inputs, signature_sha256 = _signature_inputs(module_args)
        _append_record(
            {
                "docker_after": docker_after,
                "docker_before": docker_before,
                "docker_bytes_equal": (
                    docker_bytes_before == docker_bytes_after
                ),
                "host": _bounded_text(
                    task_vars.get("inventory_hostname", "<unknown>")
                ),
                "module_name": _bounded_text(
                    kwargs.get("module_name", "<unknown>")
                ),
                "operation": _bounded_text(
                    module_args.get("operation", "<omitted>")
                ),
                "record_id": (
                    None if record_id is None else _bounded_text(record_id)
                ),
                "schema_version": 1,
                "signature_inputs": signature_inputs,
                "signature_sha256": signature_sha256,
                "state_after": state_after,
                "state_before": state_before,
                "state_bytes_equal": (
                    state_bytes_before == state_bytes_after
                ),
            }
        )
        return result
