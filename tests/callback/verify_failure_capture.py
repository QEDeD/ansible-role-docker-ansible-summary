#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Verify expected-nonzero DAS results through the real default callback."""

from __future__ import print_function

import argparse
import json
import re
import sys


ANSI_RE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
TASK_RE = re.compile(r"^TASK \[.+\] \*+$", re.MULTILINE)
ROLE_TASK_RE = re.compile(
    r"^TASK \[docker_ansible_summary : "
    r"DAS \| Observe and summarize Docker state\] \*+$",
    re.MULTILINE,
)
ITEM_EVENT_RE = re.compile(
    r"^(?:changed|failed|ok|skipping): "
    r"\[[^\]]+\] \(item=.*\)(?: =>.*)?$",
    re.MULTILINE,
)
FATAL_RE = re.compile(
    r"^fatal: \[([^\]]+)\]: FAILED! =>(.*)$",
    re.MULTILINE,
)
FAILURE_FIELDS = frozenset(
    (
        "schema_version",
        "host",
        "instance_id",
        "operation",
        "record_id",
        "observation_status",
        "failure_reason",
        "observation_reason",
        "persistence_outcome",
        "committed_result_replayable",
        "replay_guidance",
    )
)
FRAMEWORK_RESULT_FIELDS = frozenset(
    ("changed", "docker_ansible_summary_failure", "msg")
)
FORBIDDEN_TOKENS = (
    "_das_machine_result",
    "_das_failure",
    "containers",
    "stdout",
    "stderr",
    "invocation",
    "traceback",
)


def _envelope(
    host,
    instance_id,
    operation,
    record_id,
    observation_status,
    failure_reason,
    observation_reason,
    persistence_outcome,
    replayable=False,
    replay_guidance=None,
):
    return {
        "schema_version": 1,
        "host": host,
        "instance_id": instance_id,
        "operation": operation,
        "record_id": record_id,
        "observation_status": observation_status,
        "failure_reason": failure_reason,
        "observation_reason": observation_reason,
        "persistence_outcome": persistence_outcome,
        "committed_result_replayable": replayable,
        "replay_guidance": replay_guidance,
    }


STATIC_CASES = {
    "unavailable": {
        "diagnostic": "\n".join(
            (
                (
                    "DAS warning | host=failure | instance=callback-failure "
                    "| operation=status"
                ),
                (
                    "Observation unavailable | reason=docker_unavailable "
                    "| table suppressed in report_mode=none"
                ),
            )
        ),
        "envelope": _envelope(
            "failure",
            "callback-failure",
            "status",
            None,
            "unavailable",
            "observation_noncomplete",
            "docker_unavailable",
            "not_attempted",
        ),
    },
    "validation": {
        "diagnostic": "\n".join(
            (
                "DAS input error | code=invalid_input",
                (
                    "Variable operation | offending variables=1 "
                    "| values omitted"
                ),
            )
        ),
        "envelope": _envelope(
            "failure",
            None,
            None,
            None,
            None,
            "invalid_input",
            None,
            "not_attempted",
        ),
    },
    "unsafe-state": {
        "instance_id": "callback-persistence",
        "operation": "pre",
        "record_id": "callback-unsafe-state-record",
        "failure_reason": "unsafe_state_namespace",
        "persistence_outcome": "failed",
    },
    "corrupt-state": {
        "instance_id": "callback-persistence",
        "operation": "pre",
        "record_id": "callback-corrupt-state-record",
        "failure_reason": "corrupt_state",
        "persistence_outcome": "failed",
    },
    "state-size": {
        "instance_id": "callback-persistence",
        "operation": "pre",
        "record_id": "callback-state-size-record",
        "failure_reason": "state_size_limit_exceeded",
        "persistence_outcome": "failed",
    },
    "lock-timeout": {
        "instance_id": "callback-persistence",
        "operation": "pre",
        "record_id": "callback-lock-timeout-record",
        "failure_reason": "state_lock_timeout",
        "persistence_outcome": "failed",
    },
    "state-write-before": {
        "instance_id": "callback-injection",
        "operation": "pre",
        "record_id": "callback-write-before-record",
        "observation_status": "complete",
        "failure_reason": "state_write_failed",
        "persistence_outcome": "failed",
    },
    "state-write-after": {
        "instance_id": "callback-injection",
        "operation": "pre",
        "record_id": "callback-write-after-record",
        "observation_status": "complete",
        "failure_reason": "state_write_failed",
        "persistence_outcome": "failed",
        "replay_guidance": (
            "Retry with the same record_id and unchanged phase inputs"
        ),
    },
    "render-failed": {
        "instance_id": "callback-render",
        "operation": "post",
        "record_id": "callback-render-record",
        "observation_status": "complete",
        "failure_reason": "render_failed",
        "persistence_outcome": "committed",
        "replayable": True,
        "replay_guidance": (
            "Retry the retained record with report_mode=none"
        ),
    },
    "capacity": {
        "instance_id": "callback-capacity",
        "operation": "post",
        "record_id": "callback-capacity-record",
        "observation_status": "complete",
        "failure_reason": "presentation_capacity_exceeded",
        "persistence_outcome": "committed",
        "replayable": True,
        "replay_guidance": (
            "Retry the retained record with report_mode=none"
        ),
    },
}


def _parse_scalar(value):
    value = value.strip()
    if value == "null":
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    if re.match(r"^-?[0-9]+$", value):
        return int(value)
    if (
        len(value) >= 2
        and value[0] == value[-1]
        and value[0] in ("'", '"')
    ):
        if value[0] == '"':
            return json.loads(value)
        return value[1:-1].replace("''", "'")
    return value


def _parse_yaml_result(lines, fatal_index):
    outer = {}
    envelope = {}
    index = fatal_index + 1
    while index < len(lines) and lines[index].strip():
        line = lines[index]
        outer_match = re.match(r"^ {4}([a-z_]+):(.*)$", line)
        nested_match = re.match(r"^ {8}([a-z_]+): (.*)$", line)
        if nested_match:
            envelope[nested_match.group(1)] = _parse_scalar(
                nested_match.group(2)
            )
        elif outer_match:
            key = outer_match.group(1)
            remainder = outer_match.group(2).strip()
            if key == "docker_ansible_summary_failure":
                outer[key] = envelope
            else:
                outer[key] = _parse_scalar(remainder)
        else:
            raise AssertionError(
                "unexpected YAML failure-result line: %s" % line
            )
        index += 1
    if "docker_ansible_summary_failure" in outer:
        outer["docker_ansible_summary_failure"] = envelope
    return outer


def _extract_result(plain_capture, result_format):
    fatal_matches = list(FATAL_RE.finditer(plain_capture))
    if len(fatal_matches) != 1:
        raise AssertionError(
            "expected one terminal failure event, got %d"
            % len(fatal_matches)
        )
    failed_host = fatal_matches[0].group(1)
    remainder = fatal_matches[0].group(2).strip()
    if result_format == "json":
        if not remainder.startswith("{"):
            raise AssertionError("failure result did not use JSON format")
        result = json.loads(remainder)
    else:
        if remainder:
            raise AssertionError("failure result did not use YAML format")
        lines = plain_capture.splitlines()
        fatal_line = plain_capture[: fatal_matches[0].start()].count("\n")
        result = _parse_yaml_result(lines, fatal_line)
    return failed_host, result, fatal_matches[0].start()


def _dynamic_case(case, failed_host):
    if case == "conflict":
        if failed_host not in ("conflict-a", "conflict-b"):
            raise AssertionError("revision conflict failed on an unknown host")
        selected = {
            "instance_id": "callback-conflict",
            "operation": "pre",
            "record_id": "callback-" + failed_host,
            "observation_status": "complete",
            "failure_reason": "revision_conflict",
            "persistence_outcome": "conflict",
        }
    else:
        selected = STATIC_CASES[case]
    if "envelope" in selected:
        return selected["diagnostic"], selected["envelope"]

    recovery = selected.get("replay_guidance")
    diagnostic_lines = [
        (
            "DAS error | host=%s | instance=%s | operation=%s"
            % (
                failed_host,
                selected["instance_id"],
                selected["operation"],
            )
        ),
        (
            "Failure %s | no Docker process output or container data shown"
            % selected["failure_reason"]
        ),
        (
            "Record %s | persistence=%s"
            % (
                selected["record_id"],
                selected["persistence_outcome"],
            )
        ),
    ]
    if recovery is not None:
        diagnostic_lines.append("Recovery: " + recovery)
    if case == "conflict":
        diagnostic_lines.extend(
            (
                "Concurrent writer conflict | Store unchanged",
                (
                    "Recovery: Use a post-only observation or start a new "
                    "pre/post window"
                ),
            )
        )
    envelope = _envelope(
        failed_host,
        selected["instance_id"],
        selected["operation"],
        selected["record_id"],
        selected.get("observation_status"),
        selected["failure_reason"],
        None,
        selected["persistence_outcome"],
        replayable=selected.get("replayable", False),
        replay_guidance=recovery,
    )
    return "\n".join(diagnostic_lines), envelope


def _verify_recap(plain_capture, case, failed_host):
    recap_pattern = re.compile(
        r"^(failure|conflict-a|conflict-b)\s+: "
        r"ok=([0-9]+)\s+changed=([0-9]+)\s+unreachable=([0-9]+)\s+"
        r"failed=([0-9]+)\s+skipped=([0-9]+)\s+rescued=([0-9]+)\s+"
        r"ignored=([0-9]+)\s*$",
        re.MULTILINE,
    )
    recaps = {
        match.group(1): tuple(int(value) for value in match.groups()[1:])
        for match in recap_pattern.finditer(plain_capture)
    }
    if case == "conflict":
        if set(recaps) != set(("conflict-a", "conflict-b")):
            raise AssertionError("revision-conflict recap hosts differ")
        for host, values in recaps.items():
            expected = (
                (0, 0, 0, 1, 0, 0, 0)
                if host == failed_host
                else (1, 0, 0, 0, 0, 0, 0)
            )
            if values != expected:
                raise AssertionError(
                    "%s recap differs: %r" % (host, values)
                )
    else:
        expected = {"failure": (0, 0, 0, 1, 0, 0, 0)}
        if recaps != expected:
            raise AssertionError("single-host failure recap differs: %r" % recaps)


def verify(capture, result_format, color_mode, case):
    has_ansi = ANSI_RE.search(capture) is not None
    if color_mode == "off" and has_ansi:
        raise AssertionError("color-disabled failure capture contains ANSI")
    if color_mode == "on" and not has_ansi:
        raise AssertionError("color-enabled failure capture has no ANSI")
    plain = ANSI_RE.sub("", capture)

    failed_host, result, fatal_index = _extract_result(
        plain, result_format
    )
    diagnostic, expected_envelope = _dynamic_case(case, failed_host)
    if plain.count(diagnostic) != 1:
        raise AssertionError(
            "expected one exact contiguous DAS diagnostic block"
        )
    if capture.count(diagnostic) != 1:
        raise AssertionError(
            "DAS diagnostic block was decorated or split in raw callback output"
        )
    if plain.index(diagnostic) > fatal_index:
        raise AssertionError("DAS diagnostic was not emitted before failure")

    if frozenset(result) != FRAMEWORK_RESULT_FIELDS:
        raise AssertionError(
            "unexpected callback result fields: %r" % sorted(result)
        )
    if result["changed"] is not False:
        raise AssertionError("failed callback result claimed a change")
    envelope = result["docker_ansible_summary_failure"]
    if not isinstance(envelope, dict):
        raise AssertionError("public failure envelope is not a mapping")
    if frozenset(envelope) != FAILURE_FIELDS:
        raise AssertionError(
            "public failure envelope fields differ: %r" % sorted(envelope)
        )
    if envelope != expected_envelope:
        raise AssertionError(
            "failure envelope differs:\nexpected=%r\nactual=%r"
            % (expected_envelope, envelope)
        )

    bounded_result = {
        "changed": False,
        "failed": True,
        "docker_ansible_summary_failure": envelope,
    }
    encoded = json.dumps(
        bounded_result,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > 1024:
        raise AssertionError("public failure result exceeds 1024 bytes")
    if plain.count("docker_ansible_summary_failure") != 1:
        raise AssertionError("expected exactly one public failure envelope")
    for forbidden in FORBIDDEN_TOKENS:
        if forbidden in plain:
            raise AssertionError(
                "private or raw callback token escaped: %s" % forbidden
            )
    if "DAS v1 |" in plain:
        raise AssertionError("a partial or full table escaped a failed render")

    task_events = TASK_RE.findall(plain)
    role_task_events = ROLE_TASK_RE.findall(plain)
    if len(task_events) != 1 or len(role_task_events) != 1:
        raise AssertionError(
            "expected exactly the DAS role task event, got all=%d exact=%d"
            % (len(task_events), len(role_task_events))
        )
    if ITEM_EVENT_RE.search(plain) is not None:
        raise AssertionError("callback emitted an item-result event")
    for item_token in (
        "ansible_loop_var",
        '"item":',
        "\n        item:",
        '"results":',
        "\n    results:",
    ):
        if item_token in plain:
            raise AssertionError(
                "callback emitted item-result payload: %s" % item_token
            )
    if re.search(r"^ok: \[", plain, re.MULTILINE):
        raise AssertionError("successful peer payload was not suppressed")
    _verify_recap(plain, case, failed_host)
    return {
        "case": case,
        "format": result_format,
        "color": color_mode,
        "host": failed_host,
        "tasks": len(role_task_events),
        "diagnostics": plain.count(diagnostic),
        "envelope_bytes": len(encoded),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", required=True)
    parser.add_argument("--result-format", choices=("yaml", "json"), required=True)
    parser.add_argument("--color", choices=("off", "on"), required=True)
    parser.add_argument(
        "--case",
        choices=tuple(
            sorted(set(STATIC_CASES) | set(("conflict",)))
        ),
        required=True,
    )
    arguments = parser.parse_args()
    with open(arguments.capture, "r") as stream:
        evidence = verify(
            stream.read(),
            arguments.result_format,
            arguments.color,
            arguments.case,
        )
    print(
        "callback failure contract passed: "
        "case={case} format={format} color={color} host={host} "
        "tasks={tasks} diagnostics={diagnostics} "
        "envelope_bytes={envelope_bytes}".format(**evidence)
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, IOError, UnicodeError, ValueError) as error:
        print("callback failure contract failed: %s" % error, file=sys.stderr)
        sys.exit(1)
