#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Verify that raw DAS human output invalidates structured callback stdout."""

from __future__ import print_function

import argparse
import json
import re
import sys


OBSERVED_RE = re.compile(
    r"^Observed "
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{0,5}[1-9])?Z)"
    r" \| status=complete$"
)
MACHINE_RESULT_FIELDS = frozenset(
    (
        "schema_version",
        "operation",
        "instance_id",
        "record_id",
        "correlation_id",
        "observation",
        "observation_status",
        "scope_identity",
        "between_observation_delta",
        "run_window_delta",
        "baseline",
        "baseline_advanced",
        "journal_status",
        "persistence_outcome",
        "replay_outcome",
        "simulated",
        "skipped",
        "warnings",
    )
)


def _expected_report(observed_line):
    border = (
        "+"
        + ("-" * 46)
        + "+"
        + ("-" * 58)
        + "+"
        + ("-" * 12)
        + "+"
    )
    return "\n".join(
        (
            (
                "DAS v1 | host=structured | instance=callback-structured "
                "| operation=status"
            ),
            observed_line,
            border,
            "| %-44s | %-56s | %-10s |"
            % ("CONTAINER", "IMAGE", "STATE"),
            border,
            "| %-44s | %-56s | %-10s |"
            % ("das-structured", "example:1.0", "stopped"),
            border,
            (
                "Counts: authoritative_changes=0, known_rows=1, "
                "rows_with_required_gaps=0"
            ),
            "Baseline: not applicable",
            "Journal: not applicable | Persistence: not_attempted",
            "Warnings: none",
        )
    )


def _find_role_result(document):
    plays = document.get("plays")
    if not isinstance(plays, list) or len(plays) != 1:
        raise AssertionError("structured callback document has wrong play count")
    tasks = plays[0].get("tasks")
    if not isinstance(tasks, list) or len(tasks) != 2:
        raise AssertionError("structured callback document has wrong task count")
    first_hosts = tasks[0].get("hosts")
    second_hosts = tasks[1].get("hosts")
    if set(first_hosts or {}) != set(("structured",)):
        raise AssertionError("role task does not have the exact host result")
    if set(second_hosts or {}) != set(("structured",)):
        raise AssertionError("assertion task does not have the exact host result")
    assertion = second_hosts["structured"]
    if assertion.get("changed") is not False:
        raise AssertionError("registered-result assertion did not stay unchanged")
    role_result = first_hosts["structured"]
    if role_result.get("action") != "docker_ansible_summary":
        raise AssertionError("structured callback captured the wrong action")
    selected = {
        field: role_result[field]
        for field in MACHINE_RESULT_FIELDS
        if field in role_result
    }
    required_callback_fields = MACHINE_RESULT_FIELDS - frozenset(
        ("skipped",)
    )
    if not required_callback_fields.issubset(selected):
        raise AssertionError(
            "structured callback lost required visible result fields"
        )
    # The assertion task consumed the registered role result, including
    # ``skipped`` and the role-owned warning list.  This callback's serialized
    # event is allowed to filter or decorate those fields and is not the DAS
    # machine API.
    return selected


def verify(stdout, stderr):
    if "\x1b" in stdout:
        raise AssertionError("structured callback stdout contains ANSI")
    try:
        json.loads(stdout)
    except ValueError:
        whole_stdout_valid_json = False
    else:
        whole_stdout_valid_json = True
    if whole_stdout_valid_json:
        raise AssertionError(
            "human report unexpectedly formed machine-valid whole stdout"
        )

    lines = stdout.splitlines()
    if len(lines) < 12:
        raise AssertionError("structured callback stdout is truncated")
    report_lines = lines[:11]
    if OBSERVED_RE.match(report_lines[1]) is None:
        raise AssertionError("human report timestamp is not canonical UTC")
    report = "\n".join(report_lines)
    expected = _expected_report(report_lines[1])
    if report != expected or stdout.count(expected) != 1:
        raise AssertionError("structured callback human report differs")

    callback_start = len(expected) + 1
    if not stdout[callback_start:].startswith("{"):
        raise AssertionError(
            "callback-owned JSON did not immediately follow the human block"
        )
    callback_document = json.loads(stdout[callback_start:])
    machine = _find_role_result(callback_document)
    if (
        machine["operation"] != "status"
        or machine["instance_id"] != "callback-structured"
        or machine["observation_status"] != "complete"
        or machine["persistence_outcome"] != "not_attempted"
        or set(machine["observation"]["containers"])
        != set(("das-structured",))
    ):
        raise AssertionError("registered machine result has wrong semantics")
    if "DAS v1 |" in stderr:
        raise AssertionError("human report was duplicated on stderr")
    stats = callback_document.get("stats")
    if not isinstance(stats, dict) or set(stats) != set(("structured",)):
        raise AssertionError("structured callback stats have wrong hosts")
    if stats["structured"] != {
        "changed": 0,
        "failures": 0,
        "ignored": 0,
        "ok": 2,
        "rescued": 0,
        "skipped": 0,
        "unreachable": 0,
    }:
        raise AssertionError("structured callback stats differ")
    return {
        "human_report_lines": len(report_lines),
        "callback_tasks": 2,
        "whole_stdout_valid_json": whole_stdout_valid_json,
        "callback_visible_machine_fields": len(machine),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stdout", required=True)
    parser.add_argument("--stderr", required=True)
    arguments = parser.parse_args()
    with open(arguments.stdout, "r") as stream:
        stdout = stream.read()
    with open(arguments.stderr, "r") as stream:
        stderr = stream.read()
    evidence = verify(stdout, stderr)
    print(
        "structured callback negative contract passed: "
        "human_report_lines={human_report_lines} "
        "callback_tasks={callback_tasks} "
        "whole_stdout_valid_json={whole_stdout_valid_json} "
        "callback_visible_machine_fields="
        "{callback_visible_machine_fields}".format(
            **evidence
        )
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, IOError, KeyError, TypeError, ValueError) as error:
        print(
            "structured callback negative contract failed: %s" % error,
            file=sys.stderr,
        )
        sys.exit(1)
