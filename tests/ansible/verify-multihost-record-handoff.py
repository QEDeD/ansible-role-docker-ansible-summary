# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Verify the callback-visible execution surface of the handoff play."""

from __future__ import annotations

import argparse
import json
import pathlib
import re


HOSTS = ("alpha", "bravo")
ROLE_TASK_NAME = (
    "docker_ansible_summary : DAS | Observe and summarize Docker state"
)
HARNESS_TASK_NAMES = (
    "DAS handoff contract | Preserve the generated pre identity",
    "DAS handoff contract | Validate the generated pre identity",
    "DAS handoff contract | Preserve the post result",
    "DAS handoff contract | Read the per-host durable state",
    "DAS handoff contract | Read the per-host Docker process evidence",
    "DAS handoff contract | Decode per-host evidence",
    "DAS handoff contract | Validate exact per-host execution and state",
    "DAS handoff contract | Validate cross-host isolation",
)
TASK_HEADER_RE = re.compile(r"^TASK \[(?P<name>.*?)\] \*+$")
HOST_RESULT_RE = re.compile(
    r"^(?:ok|changed): \[(alpha|bravo)\](?: =>.*)?$",
    re.MULTILINE,
)


def _task_blocks(capture: str) -> list[tuple[str, str]]:
    lines = capture.splitlines()
    starts = []
    for index, line in enumerate(lines):
        match = TASK_HEADER_RE.match(line)
        if match is not None:
            starts.append((index, match.group("name")))

    blocks: list[tuple[str, str]] = []
    for position, (start, name) in enumerate(starts):
        end = len(lines)
        if position + 1 < len(starts):
            end = starts[position + 1][0]
        blocks.append((name, "\n".join(lines[start:end])))
    return blocks


def _load_json_lines(source: pathlib.Path, maximum_bytes: int) -> list[object]:
    payload = source.read_bytes()
    if len(payload) > maximum_bytes:
        raise AssertionError("%s exceeds its test-evidence bound" % source)
    lines = payload.decode("utf-8").splitlines()
    return [json.loads(line) for line in lines]


def _verify_spy_records(spy_log: pathlib.Path) -> int:
    records = _load_json_lines(spy_log, 4096)
    if len(records) != 4:
        raise AssertionError(
            "expected four action-spy records, found %d" % len(records)
        )
    expected_keys = {
        "host",
        "module_name",
        "operation",
        "schema_version",
    }
    for record in records:
        if not isinstance(record, dict) or set(record) != expected_keys:
            raise AssertionError("action-spy record has an unexpected shape")
        if record["schema_version"] != 1:
            raise AssertionError("action-spy schema version is not 1")
        if record["module_name"] != "docker_ansible_summary":
            raise AssertionError("action-spy intercepted an unexpected module")
    observed = sorted(
        (record["host"], record["operation"]) for record in records
    )
    expected = sorted(
        (host, operation)
        for host in HOSTS
        for operation in ("pre", "post")
    )
    if observed != expected:
        raise AssertionError(
            "action-spy phase/host records differ: %r" % observed
        )
    return len(records)


def _verify_docker_processes(log_root: pathlib.Path) -> int:
    total = 0
    expected_prefixes = (
        ["container", "ls"],
        ["container", "inspect"],
        ["container", "ls"],
        ["container", "inspect"],
    )
    for host in HOSTS:
        calls = _load_json_lines(log_root / (host + ".jsonl"), 16384)
        if len(calls) != 4:
            raise AssertionError(
                "%s fake-Docker log has %d calls, expected 4"
                % (host, len(calls))
            )
        if any(not isinstance(call, list) for call in calls):
            raise AssertionError("%s fake-Docker call is not an argv list" % host)
        prefixes = [call[0:2] for call in calls]
        if prefixes != list(expected_prefixes):
            raise AssertionError(
                "%s fake-Docker process sequence differs: %r"
                % (host, prefixes)
            )
        total += len(calls)
    if total != 8:
        raise AssertionError(
            "fake-Docker evidence has %d processes, expected 8" % total
        )
    return total


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", required=True, type=pathlib.Path)
    parser.add_argument(
        "--docker-log-root",
        required=True,
        type=pathlib.Path,
    )
    parser.add_argument("--spy-log", required=True, type=pathlib.Path)
    arguments = parser.parse_args()

    capture = arguments.capture.read_text(encoding="utf-8")
    task_blocks = _task_blocks(capture)
    task_names = [name for name, _block in task_blocks]
    known_names = set(HARNESS_TASK_NAMES) | {ROLE_TASK_NAME}
    unknown_names = sorted(set(task_names) - known_names)
    if unknown_names:
        raise AssertionError(
            "callback contains unclassified task headings: %r"
            % unknown_names
        )
    if task_names.count(ROLE_TASK_NAME) != 2:
        raise AssertionError(
            "expected exactly two role-owned task events, found %d"
            % task_names.count(ROLE_TASK_NAME)
        )
    for name in HARNESS_TASK_NAMES:
        if task_names.count(name) != 1:
            raise AssertionError(
                "expected exactly one named harness task %r, found %d"
                % (name, task_names.count(name))
            )

    role_blocks = [
        block for name, block in task_blocks if name == ROLE_TASK_NAME
    ]
    role_host_results = 0
    for index, block in enumerate(role_blocks, start=1):
        hosts = HOST_RESULT_RE.findall(block)
        if sorted(hosts) != ["alpha", "bravo"]:
            raise AssertionError(
                "role task %d did not execute exactly once for each host: %r"
                % (index, hosts)
            )
        role_host_results += len(hosts)

    module_invocations = _verify_spy_records(arguments.spy_log)
    docker_processes = _verify_docker_processes(arguments.docker_log_root)

    print(
        "multihost handoff callback contract: "
        "role_tasks=2 harness_tasks=%d role_host_results=%d "
        "module_invocations=%d docker_processes=%d"
        % (
            len(HARNESS_TASK_NAMES),
            role_host_results,
            module_invocations,
            docker_processes,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
