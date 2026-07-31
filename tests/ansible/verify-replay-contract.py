# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Verify real-Ansible retained replay behavior and immutable evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re


ROLE_TASK_NAME = (
    "docker_ansible_summary : DAS | Observe and summarize Docker state"
)
HARNESS_TASK_NAMES = (
    "DAS replay contract | Preserve the pre result",
    "DAS replay contract | Preserve the first post result",
    "DAS replay contract | Validate retained replay semantics",
)
TASK_HEADER_RE = re.compile(r"^TASK \[(?P<name>.*?)\] \*+$")
HOST_RESULT_RE = re.compile(
    r"^(?:ok|changed): \[localhost\](?: =>.*)?$",
    re.MULTILINE,
)
OBSERVED_RE = re.compile(
    r"^Observed "
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{0,5}[1-9])?Z)"
    r" \| status=complete(?P<replay> \| replay=idempotent)?$"
)
RECORD_ID_RE = re.compile(r"\Adas-[0-9a-f]{32}\Z")


def _load_json_lines(source: pathlib.Path, maximum_bytes: int) -> list[object]:
    payload = source.read_bytes()
    if len(payload) > maximum_bytes:
        raise AssertionError("%s exceeds its evidence bound" % source)
    return [
        json.loads(line)
        for line in payload.decode("utf-8").splitlines()
    ]


def _task_blocks(capture: str) -> list[tuple[str, str]]:
    lines = capture.splitlines()
    starts = []
    for index, line in enumerate(lines):
        match = TASK_HEADER_RE.match(line)
        if match is not None:
            starts.append((index, match.group("name")))
    blocks = []
    for position, (start, name) in enumerate(starts):
        end = (
            starts[position + 1][0]
            if position + 1 < len(starts)
            else len(lines)
        )
        blocks.append((name, "\n".join(lines[start:end])))
    return blocks


def _report_lines(block: str) -> list[str]:
    lines = block.splitlines()
    starts = [
        index for index, line in enumerate(lines) if line.startswith("DAS v1 |")
    ]
    if not starts:
        return []
    if len(starts) != 1:
        raise AssertionError("role task emitted multiple DAS report headers")
    start = starts[0]
    for end in range(start + 1, len(lines)):
        if lines[end].startswith("Warnings:"):
            return lines[start : end + 1]
    raise AssertionError("DAS report block has no warnings terminator")


def _verify_callback_surface(capture: str) -> tuple[int, int]:
    task_blocks = _task_blocks(capture)
    task_names = [name for name, _block in task_blocks]
    known = set(HARNESS_TASK_NAMES) | {ROLE_TASK_NAME}
    unknown = sorted(set(task_names) - known)
    if unknown:
        raise AssertionError(
            "callback contains unclassified task headings: %r" % unknown
        )
    if task_names.count(ROLE_TASK_NAME) != 3:
        raise AssertionError("expected exactly three role task events")
    for name in HARNESS_TASK_NAMES:
        if task_names.count(name) != 1:
            raise AssertionError(
                "expected exactly one harness task %r" % name
            )

    role_blocks = [
        block for name, block in task_blocks if name == ROLE_TASK_NAME
    ]
    for index, block in enumerate(role_blocks, start=1):
        if len(HOST_RESULT_RE.findall(block)) != 1:
            raise AssertionError(
                "role task %d did not return exactly one ok result" % index
            )
        if re.search(r"^changed: \[localhost\]", block, re.MULTILINE):
            raise AssertionError("DAS role action unexpectedly changed state")

    pre_report = _report_lines(role_blocks[0])
    first_post_report = _report_lines(role_blocks[1])
    replay_report = _report_lines(role_blocks[2])
    if pre_report:
        raise AssertionError("final-mode complete pre emitted a report")
    if not first_post_report or not replay_report:
        raise AssertionError("a final-mode post report is missing")

    expected_header = (
        "DAS v1 | host=localhost | instance=replay-proof | operation=post"
    )
    if first_post_report[0] != expected_header:
        raise AssertionError("first post report header differs")
    if replay_report[0] != expected_header:
        raise AssertionError("replay report header differs")

    first_observed = OBSERVED_RE.match(first_post_report[1])
    replay_observed = OBSERVED_RE.match(replay_report[1])
    if first_observed is None or first_observed.group("replay") is not None:
        raise AssertionError("first post observed line is not normal")
    if replay_observed is None or replay_observed.group("replay") is None:
        raise AssertionError("replay observed line lacks its annotation")
    if first_observed.group("timestamp") != replay_observed.group("timestamp"):
        raise AssertionError("replay did not retain the post observation time")

    if (
        "Journal: complete | Persistence: committed"
        not in first_post_report
    ):
        raise AssertionError("first post committed footer is missing")
    if (
        "Journal: complete | Persistence: not_attempted"
        not in replay_report
    ):
        raise AssertionError("replay no-persistence footer is missing")
    if "Counts: unchanged=1, total=1" not in first_post_report:
        raise AssertionError("first post run-window counts differ")
    if "Counts: unchanged=1, total=1" not in replay_report:
        raise AssertionError("replay run-window counts differ")
    if not any(
        all(label in line for label in ("CONTAINER", "BEFORE", "AFTER", "CHANGE"))
        for line in first_post_report
    ):
        raise AssertionError("first post run-window table header is missing")

    normalized_replay = [
        line.replace(" | replay=idempotent", "").replace(
            "Persistence: not_attempted",
            "Persistence: committed",
        )
        for line in replay_report
    ]
    if normalized_replay != first_post_report:
        raise AssertionError(
            "replay report differs beyond replay and persistence annotations"
        )
    return len(role_blocks), len(first_post_report) + len(replay_report)


def _verify_spy_records(records: list[object]) -> tuple[int, str]:
    if len(records) != 3:
        raise AssertionError(
            "expected three real module invocations, found %d" % len(records)
        )
    expected_keys = {
        "docker_after",
        "docker_before",
        "docker_bytes_equal",
        "host",
        "module_name",
        "operation",
        "record_id",
        "schema_version",
        "signature_inputs",
        "signature_sha256",
        "state_after",
        "state_before",
        "state_bytes_equal",
    }
    for record in records:
        if not isinstance(record, dict) or set(record) != expected_keys:
            raise AssertionError("replay-spy record has an unexpected shape")
        if record["schema_version"] != 1:
            raise AssertionError("replay-spy schema version differs")
        if record["host"] != "localhost":
            raise AssertionError("replay-spy host differs")
        if record["module_name"] != "docker_ansible_summary":
            raise AssertionError("replay-spy module differs")
    if [record["operation"] for record in records] != [
        "pre",
        "post",
        "post",
    ]:
        raise AssertionError("real module operation sequence differs")

    record_id = records[1]["record_id"]
    if not isinstance(record_id, str) or RECORD_ID_RE.match(record_id) is None:
        raise AssertionError("first post record ID differs")
    if records[0]["record_id"] is not None:
        raise AssertionError("generated pre unexpectedly supplied a record ID")
    if records[2]["record_id"] != record_id:
        raise AssertionError("replay did not use the identical record ID")
    expected_signature = {
        "correlation_id": None,
        "instance_id": "replay-proof",
        "operation": "post",
        "scope": ["das-replay-*"],
    }
    if records[1]["signature_inputs"] != expected_signature:
        raise AssertionError("first post signature inputs differ")
    if records[2]["signature_inputs"] != expected_signature:
        raise AssertionError("replay signature inputs differ")
    if records[2]["signature_sha256"] != records[1]["signature_sha256"]:
        raise AssertionError("replay phase signature differs")

    pre, first_post, replay = records
    if pre["docker_before"]["lines"] != 0:
        raise AssertionError("pre Docker evidence did not begin empty")
    if pre["docker_after"]["lines"] != 2 or pre["docker_bytes_equal"]:
        raise AssertionError("pre did not perform exactly two Docker calls")
    if first_post["docker_before"]["lines"] != 2:
        raise AssertionError("first post Docker evidence began at the wrong count")
    if (
        first_post["docker_after"]["lines"] != 4
        or first_post["docker_bytes_equal"]
    ):
        raise AssertionError(
            "first post did not perform exactly two Docker calls"
        )
    if replay["docker_before"]["lines"] != 4:
        raise AssertionError("replay Docker evidence began at the wrong count")
    if replay["docker_after"] != replay["docker_before"]:
        raise AssertionError("replay changed Docker process evidence")
    if not replay["docker_bytes_equal"]:
        raise AssertionError("replay emitted a Docker CLI process")

    if pre["state_before"]["state"]["exists"]:
        raise AssertionError("pre did not begin from absent state")
    if pre["state_after"]["state"]["revision"] != 1:
        raise AssertionError("pre did not commit revision 1")
    if first_post["state_before"] != pre["state_after"]:
        raise AssertionError("first post did not begin from the pre state")
    if first_post["state_after"]["state"]["revision"] != 2:
        raise AssertionError("first post did not commit revision 2")
    committed_paths = first_post["state_after"]
    expected_modes = {
        "directory": 0o700,
        "lock": 0o600,
        "state": 0o600,
    }
    for name, mode in expected_modes.items():
        if not committed_paths[name]["exists"]:
            raise AssertionError("committed %s evidence is absent" % name)
        if committed_paths[name]["mode"] != mode:
            raise AssertionError("committed %s mode differs" % name)
    if first_post["state_bytes_equal"]:
        raise AssertionError("first post did not change canonical state bytes")
    if (
        first_post["state_before"]["state"]["inode"]
        == first_post["state_after"]["state"]["inode"]
    ):
        raise AssertionError("first post did not atomically replace state")

    if replay["state_before"] != first_post["state_after"]:
        raise AssertionError("replay did not begin from committed post state")
    if replay["state_after"] != replay["state_before"]:
        raise AssertionError("replay changed persistence metadata")
    if not replay["state_bytes_equal"]:
        raise AssertionError("replay changed canonical state bytes")
    if not replay["state_after"]["state"]["canonical"]:
        raise AssertionError("replay state bytes are not canonical")
    return len(records), record_id


def _verify_final_state(
    state_file: pathlib.Path,
    replay_snapshot: dict,
    expected_record_id: str,
) -> tuple[int, str]:
    payload = state_file.read_bytes()
    if len(payload) > 1048576:
        raise AssertionError("final state exceeds replay evidence bound")
    store = json.loads(payload.decode("utf-8"))
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
    if payload != canonical:
        raise AssertionError("final state is not exact canonical JSON")
    if store.get("revision") != 2:
        raise AssertionError("final state revision is not 2")
    journal = store.get("journal")
    if not isinstance(journal, list) or len(journal) != 1:
        raise AssertionError("final state journal differs")
    if journal[0].get("record_id") != expected_record_id:
        raise AssertionError("final state retained the wrong record")
    if journal[0].get("status") != "complete":
        raise AssertionError("final state record is not complete")

    metadata = state_file.stat()
    digest = hashlib.sha256(payload).hexdigest()
    expected = replay_snapshot["state"]
    checks = {
        "inode": metadata.st_ino,
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
        "size": metadata.st_size,
        "sha256": digest,
        "revision": store["revision"],
        "canonical": True,
        "exists": True,
        "mode": metadata.st_mode & 0o777,
    }
    if checks != expected:
        raise AssertionError("final state differs from replay-spy evidence")
    return store["revision"], digest


def _verify_docker_log(docker_log: pathlib.Path) -> int:
    calls = _load_json_lines(docker_log, 16384)
    if len(calls) != 4:
        raise AssertionError(
            "expected four Docker CLI processes, found %d" % len(calls)
        )
    prefixes = [call[0:2] for call in calls]
    if prefixes != [
        ["container", "ls"],
        ["container", "inspect"],
        ["container", "ls"],
        ["container", "inspect"],
    ]:
        raise AssertionError("Docker CLI process sequence differs")
    return len(calls)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", required=True, type=pathlib.Path)
    parser.add_argument("--docker-log", required=True, type=pathlib.Path)
    parser.add_argument("--spy-log", required=True, type=pathlib.Path)
    parser.add_argument("--state-file", required=True, type=pathlib.Path)
    arguments = parser.parse_args()

    capture = arguments.capture.read_text(encoding="utf-8")
    role_tasks, report_lines = _verify_callback_surface(capture)
    records = _load_json_lines(arguments.spy_log, 16384)
    module_invocations, record_id = _verify_spy_records(records)
    docker_processes = _verify_docker_log(arguments.docker_log)
    revision, digest = _verify_final_state(
        arguments.state_file,
        records[-1]["state_after"],
        record_id,
    )
    print(
        "retained replay contract passed: role_tasks=%d "
        "module_invocations=%d docker_processes=%d "
        "replay_docker_processes=0 replay_persistence_writes=0 "
        "state_bytes_equal=true persistence_metadata_equal=true "
        "state_revision=%d state_inode=%d state_mtime_ns=%d "
        "state_sha256=%s replay_signature_sha256=%s report_lines=%d"
        % (
            role_tasks,
            module_invocations,
            docker_processes,
            revision,
            records[-1]["state_after"]["state"]["inode"],
            records[-1]["state_after"]["state"]["mtime_ns"],
            digest,
            records[-1]["signature_sha256"],
            report_lines,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
