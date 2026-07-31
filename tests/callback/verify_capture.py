#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Verify atomic DAS blocks in one default-callback Ansible capture."""

from __future__ import print_function

import argparse
import re
import sys


HOSTS = {
    "alpha": "das-alpha",
    "bravo": "das-bravo",
}
REPORT_LINE_COUNT = 11
OBSERVED_RE = re.compile(
    r"^Observed "
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{0,5}[1-9])?Z)"
    r" \| status=complete$"
)
TASK_RE = re.compile(r"^TASK \[(?P<name>.+)\] \*+$", re.MULTILINE)
ANSI_RE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def _fail(message):
    raise AssertionError(message)


def _expected_block(host, container_name, observed_line):
    border = (
        "+"
        + ("-" * 46)
        + "+"
        + ("-" * 58)
        + "+"
        + ("-" * 12)
        + "+"
    )
    table_header = "| %-44s | %-56s | %-10s |" % (
        "CONTAINER",
        "IMAGE",
        "STATE",
    )
    table_row = "| %-44s | %-56s | %-10s |" % (
        container_name,
        "example:1.0",
        "stopped",
    )
    return "\n".join(
        [
            (
                "DAS v1 | host=%s | instance=callback-%s "
                "| operation=status"
            )
            % (host, host),
            observed_line,
            border,
            table_header,
            border,
            table_row,
            border,
            (
                "Counts: authoritative_changes=0, known_rows=1, "
                "rows_with_required_gaps=0"
            ),
            "Baseline: not applicable",
            "Journal: not applicable | Persistence: not_attempted",
            "Warnings: none",
        ]
    )


def _verify_result_format(capture, result_format):
    assertion_marker = (
        "ok: [alpha] => \n    changed: false"
        if result_format == "yaml"
        else 'ok: [alpha] => {\n    "changed": false,'
    )
    if assertion_marker not in capture:
        _fail(
            "default callback did not expose the requested %s result format"
            % result_format
        )


def verify(capture, result_format, color_mode):
    has_ansi = ANSI_RE.search(capture) is not None
    if color_mode == "off" and has_ansi:
        _fail("color-disabled capture contains an ANSI escape sequence")
    if color_mode == "on" and not has_ansi:
        _fail("color-enabled callback capture contains no ANSI decoration")

    plain_capture = ANSI_RE.sub("", capture)
    lines = plain_capture.splitlines()
    report_headers = [
        index for index, line in enumerate(lines) if line.startswith("DAS v1 |")
    ]
    if len(report_headers) != len(HOSTS):
        _fail("expected exactly two DAS report headers")

    for host, container_name in sorted(HOSTS.items()):
        header = (
            "DAS v1 | host=%s | instance=callback-%s | operation=status"
            % (host, host)
        )
        indexes = [index for index, line in enumerate(lines) if line == header]
        if len(indexes) != 1:
            _fail("%s report header was not unique" % host)
        start = indexes[0]
        block_lines = lines[start : start + REPORT_LINE_COUNT]
        if len(block_lines) != REPORT_LINE_COUNT:
            _fail("%s report block was truncated" % host)
        match = OBSERVED_RE.match(block_lines[1])
        if match is None:
            _fail("%s observed-at line is not canonical UTC" % host)
        block = "\n".join(block_lines)
        if ANSI_RE.search(
            "\n".join(capture.splitlines()[start : start + REPORT_LINE_COUNT])
        ):
            _fail("%s DAS report block contains callback color" % host)
        expected = _expected_block(host, container_name, block_lines[1])
        if block != expected:
            _fail("%s report block differs from the exact contract" % host)
        if plain_capture.count(expected) != 1:
            _fail("%s report block was not unique and contiguous" % host)
        for other_host, other_container in HOSTS.items():
            if other_host == host:
                continue
            forbidden = (
                "host=" + other_host,
                "instance=callback-" + other_host,
                other_container,
            )
            if any(token in block for token in forbidden):
                _fail("%s report contains %s host data" % (host, other_host))

    task_names = TASK_RE.findall(plain_capture)
    task_count = len(task_names)
    if task_count != 2:
        _fail("expected exactly two linear task events, got %d" % task_count)
    expected_role_task = (
        "docker_ansible_summary : DAS | Observe and summarize Docker state"
    )
    expected_harness_task = (
        "DAS callback contract | Validate the machine result"
    )
    if task_names.count(expected_role_task) != 1:
        _fail("expected exactly one role-owned task start")
    if task_names.count(expected_harness_task) != 1:
        _fail("expected exactly one harness assertion task start")
    if sorted(task_names) != sorted(
        (expected_role_task, expected_harness_task)
    ):
        _fail("callback capture contains an unclassified task event")

    host_result_count = 0
    for host in sorted(HOSTS):
        count = len(
            re.findall(
                r"^ok: \[%s\](?: => .*)?$" % re.escape(host),
                plain_capture,
                re.MULTILINE,
            )
        )
        if count != 2:
            _fail("%s emitted %d successful host events, expected 2" % (host, count))
        host_result_count += count
        recap = re.compile(
            r"^%s\s+: ok=2\s+changed=0\s+unreachable=0\s+"
            r"failed=0\s+skipped=0\s+rescued=0\s+ignored=0\s*$"
            % re.escape(host),
            re.MULTILINE,
        )
        if recap.search(plain_capture) is None:
            _fail("%s recap is not the exact successful contract" % host)

    _verify_result_format(plain_capture, result_format)
    return {
        "format": result_format,
        "color": color_mode,
        "tasks": task_count,
        "role_tasks": 1,
        "harness_tasks": 1,
        "host_results": host_result_count,
        "reports": len(report_headers),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", required=True)
    parser.add_argument("--result-format", choices=("yaml", "json"), required=True)
    parser.add_argument("--color", choices=("off", "on"), required=True)
    arguments = parser.parse_args()

    with open(arguments.capture, "r") as capture_file:
        capture = capture_file.read()
    evidence = verify(capture, arguments.result_format, arguments.color)
    print(
        "callback contract passed: "
        "format={format} color={color} tasks={tasks} role_tasks={role_tasks} "
        "harness_tasks={harness_tasks} host_results={host_results} "
        "reports={reports}".format(**evidence)
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, IOError, UnicodeError) as error:
        print("callback contract failed: %s" % error, file=sys.stderr)
        sys.exit(1)
