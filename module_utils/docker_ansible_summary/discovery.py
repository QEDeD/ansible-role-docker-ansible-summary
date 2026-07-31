# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Bounded Docker CLI discovery for Docker Ansible Summary.

The adapter deliberately returns only the canonical observation allowlist. It
never returns command lines, stdout, stderr, or a Docker inspect document.
"""

from __future__ import absolute_import, division, print_function

import datetime
import errno
import fnmatch
import json
import os
import re
import selectors
import shutil
import subprocess
import time
import uuid

from .constants import (
    CONTAINER_ID_PATTERN,
    CONTAINER_NAME_PATTERN,
    DOCKER_WARNING_BY_REASON as WARNING_BY_REASON,
    IMAGE_ID_PATTERN,
    RUNTIME_STATES,
)

CATALOGUE_MAX_ROWS = 4096
CONTAINER_CHUNK_MAX_ITEMS = 100
ARGV_MAX_BYTES = 8192
STDOUT_MAX_BYTES = 2097152
STDERR_MAX_BYTES = 65536
OUTPUT_LINE_MAX_BYTES = 8192

CONTAINER_ID_RE = re.compile(CONTAINER_ID_PATTERN)
IMAGE_ID_RE = re.compile(IMAGE_ID_PATTERN)
CONTAINER_NAME_RE = re.compile(CONTAINER_NAME_PATTERN)
TIMESTAMP_RE = re.compile(
    r"\A([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.([0-9]{1,9}))?Z\Z"
)

CATALOGUE_FORMAT = '{"id":{{json .ID}},"name":{{json .Names}}}'
INSPECT_FORMAT = (
    '{"container_id":{{json .Id}},"created_at":{{json .Created}},'
    '"finished_at":{{json .State.FinishedAt}},'
    '"full_image_reference":{{json .Config.Image}},'
    '"image_id":{{json .Image}},"name":{{json .Name}},'
    '"restart_count":{{json .RestartCount}},'
    '"runtime_state":{{json .State.Status}},'
    '"started_at":{{json .State.StartedAt}}}'
)


class DiscoveryProtocolError(ValueError):
    """Raised for bounded Docker output that violates the v1 protocol."""


class DiscoveryCapacityError(ValueError):
    """Raised when the trustworthy catalogue exceeds its fixed v1 limit."""


class InspectFault(ValueError):
    """A safe, classified inspect-chunk failure."""

    def __init__(self, reason, gap=None):
        ValueError.__init__(self, reason)
        self.reason = reason
        self.gap = gap


class _DuplicateJsonKey(ValueError):
    pass


_AUTO_DOCKER_PATH = object()


def _object_without_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey()
        result[key] = value
    return result


def _reject_json_constant(_value):
    raise ValueError("non-finite JSON constant")


def _load_protocol_object(line):
    return json.loads(
        line,
        object_pairs_hook=_object_without_duplicate_keys,
        parse_constant=_reject_json_constant,
    )


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


def format_utc_timestamp(value):
    """Format a naive/UTC datetime using the canonical v1 timestamp form."""

    if value.tzinfo is not None:
        value = value.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    base = value.strftime("%Y-%m-%dT%H:%M:%S")
    fraction = ("%06d" % value.microsecond).rstrip("0")
    return base + (("." + fraction) if fraction else "") + "Z"


def normalize_timestamp(value, semantic_zero_is_null=False):
    """Return ``(normalized, gap)`` for a Docker timestamp."""

    if value is None:
        return None, True
    if not isinstance(value, str):
        return None, True
    if value == "0001-01-01T00:00:00Z":
        return None, not semantic_zero_is_null
    match = TIMESTAMP_RE.match(value)
    if not match:
        return None, True
    try:
        datetime.datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None, True
    fraction = match.group(2)
    if fraction:
        fraction = fraction.rstrip("0")
    return match.group(1) + (("." + fraction) if fraction else "") + "Z", False


def _printable_ascii(value, maximum):
    if not isinstance(value, str) or not value:
        return False
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        return False
    if len(encoded) > maximum:
        return False
    return all(0x21 <= byte <= 0x7E for byte in bytearray(encoded))


def normalize_container_name(value):
    if not isinstance(value, str):
        return None
    if value.startswith("/"):
        value = value[1:]
    if not CONTAINER_NAME_RE.match(value):
        return None
    return value


def argv_size(argv):
    return sum(len(os.fsencode(argument)) + 1 for argument in argv)


def chunk_identifiers(fixed_argv, identifiers, max_items=CONTAINER_CHUNK_MAX_ITEMS,
                      max_bytes=ARGV_MAX_BYTES):
    """Partition stable identifiers by both item and complete-argv byte caps."""

    chunks = []
    current = []
    for identifier in identifiers:
        candidate = current + [identifier]
        if len(candidate) <= max_items and argv_size(fixed_argv + candidate) <= max_bytes:
            current = candidate
            continue
        if current:
            chunks.append(current)
            current = []
        if argv_size(fixed_argv + [identifier]) > max_bytes:
            raise InspectFault("inspect_identifier_argv_too_large")
        current = [identifier]
    if current:
        chunks.append(current)
    return chunks


def _line_limit_exceeded(data):
    if not data:
        return False
    return any(
        len(line) > OUTPUT_LINE_MAX_BYTES
        for line in data.split(b"\n")
    )


def _terminate_and_reap(process):
    if process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=0.25)
    except Exception:
        try:
            process.kill()
        except Exception:
            pass
        try:
            process.wait(timeout=0.25)
        except Exception:
            pass


def run_bounded_process(argv, timeout_seconds, popen_factory=subprocess.Popen,
                        monotonic=time.monotonic):
    """Run one no-shell process while draining both bounded byte streams."""

    deadline = monotonic() + max(0.0, float(timeout_seconds))
    process = popen_factory(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        close_fds=True,
    )
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    streams = {"stdout": process.stdout, "stderr": process.stderr}
    for label, stream in streams.items():
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, label)

    status = "ok"
    try:
        while selector.get_map():
            remaining = deadline - monotonic()
            if remaining <= 0:
                status = "timeout"
                break
            events = selector.select(remaining)
            if not events:
                status = "timeout"
                break
            for key, _mask in events:
                label = key.data
                try:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffers[label].extend(chunk)
                cap = STDOUT_MAX_BYTES if label == "stdout" else STDERR_MAX_BYTES
                if len(buffers[label]) > cap or _line_limit_exceeded(buffers[label]):
                    status = "output_limit"
                    break
            if status != "ok":
                break
        if status != "ok":
            _terminate_and_reap(process)
        else:
            remaining = deadline - monotonic()
            if remaining <= 0:
                status = "timeout"
                _terminate_and_reap(process)
            else:
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    status = "timeout"
                    _terminate_and_reap(process)
    finally:
        selector.close()
        for stream in streams.values():
            try:
                stream.close()
            except Exception:
                pass

    return {
        "status": status,
        "returncode": process.returncode,
        "stdout": bytes(buffers["stdout"]),
        "stderr": bytes(buffers["stderr"]),
    }


def _decode_protocol_lines(data):
    if not data:
        return []
    if _line_limit_exceeded(data):
        raise DiscoveryProtocolError("protocol line exceeds fixed limit")
    if b"\r" in data:
        raise DiscoveryProtocolError("protocol requires LF line endings")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise DiscoveryProtocolError("invalid UTF-8")
    if not text.endswith("\n"):
        raise DiscoveryProtocolError("unterminated protocol line")
    lines = text[:-1].split("\n")
    if any(not line for line in lines):
        raise DiscoveryProtocolError("blank protocol line")
    return lines


def parse_catalogue(data):
    """Parse exact catalogue JSON lines into stable safe rows."""

    rows = []
    seen_ids = set()
    seen_names = set()
    for line in _decode_protocol_lines(data):
        try:
            item = _load_protocol_object(line)
        except (TypeError, ValueError, _DuplicateJsonKey):
            raise DiscoveryProtocolError("invalid catalogue JSON")
        if not isinstance(item, dict) or set(item) != {"id", "name"}:
            raise DiscoveryProtocolError("invalid catalogue object")
        container_id = item["id"]
        if not isinstance(container_id, str) or not CONTAINER_ID_RE.match(container_id):
            raise DiscoveryProtocolError("invalid catalogue ID")
        if container_id in seen_ids:
            raise DiscoveryProtocolError("duplicate catalogue ID")
        seen_ids.add(container_id)
        if item["name"] is not None and not isinstance(item["name"], str):
            raise DiscoveryProtocolError("invalid catalogue name type")
        name = normalize_container_name(item["name"])
        if name is not None:
            if name in seen_names:
                raise DiscoveryProtocolError("duplicate catalogue name")
            seen_names.add(name)
        rows.append({"container_id": container_id, "name": name})
        if len(rows) > CATALOGUE_MAX_ROWS:
            raise DiscoveryCapacityError("catalogue capacity exceeded")
    rows.sort(key=lambda row: (
        row["name"] is None,
        (row["name"] or "").encode("ascii"),
        row["container_id"],
    ))
    return rows


def _scope_matches(name, scope):
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in scope["patterns"])


def _normalize_restart_count(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None, True
    return value, False


def _validate_required_string(value, field):
    if value is None or value == "":
        raise InspectFault("required_field_missing", field)
    if not isinstance(value, str):
        raise InspectFault("docker_protocol_error", field)
    return value


def normalize_inspect_item(item, expected_id, expected_name):
    """Normalize one structurally valid inspect projection.

    The return value is ``(container, metadata_gaps, partial_reason)``.
    Catalogue/inspect identity faults and structurally invalid values still
    fail the whole atomic chunk. Missing non-identity required evidence and an
    unsupported but syntactically valid runtime state are retained
    field-locally as ``None`` plus an exact gap.
    """

    expected_keys = {
        "container_id",
        "created_at",
        "finished_at",
        "full_image_reference",
        "image_id",
        "name",
        "restart_count",
        "runtime_state",
        "started_at",
    }
    if not isinstance(item, dict) or set(item) != expected_keys:
        raise InspectFault("docker_protocol_error")

    container_id = _validate_required_string(item["container_id"], "container_id")
    if not CONTAINER_ID_RE.match(container_id):
        raise InspectFault("docker_protocol_error", "container_id")
    if container_id != expected_id:
        raise InspectFault("required_field_missing", "container_id")

    if not isinstance(item["name"], str):
        raise InspectFault("docker_protocol_error", "name")
    name = normalize_container_name(item["name"])
    if name is None or name != expected_name:
        raise InspectFault("scope_membership_unknown", "name")

    gaps = []
    partial_reason = None

    full_reference = item["full_image_reference"]
    if full_reference is None or full_reference == "":
        full_reference = None
        gaps.append(name + ".full_image_reference")
        partial_reason = "required_field_missing"
    elif not isinstance(full_reference, str):
        raise InspectFault("docker_protocol_error", "full_image_reference")
    elif not _printable_ascii(full_reference, 4096):
        raise InspectFault("docker_protocol_error", "full_image_reference")

    image_id = item["image_id"]
    if image_id is None or image_id == "":
        image_id = None
        gaps.append(name + ".image_id")
        partial_reason = partial_reason or "required_field_missing"
    elif not isinstance(image_id, str):
        raise InspectFault("docker_protocol_error", "image_id")
    elif not IMAGE_ID_RE.match(image_id):
        raise InspectFault("docker_protocol_error", "image_id")

    raw_state = item["runtime_state"]
    if raw_state is None or raw_state == "":
        runtime_state = None
        gaps.append(name + ".runtime_state")
        partial_reason = partial_reason or "required_field_missing"
    elif not isinstance(raw_state, str):
        raise InspectFault("docker_protocol_error", "runtime_state")
    else:
        runtime_state = "stopped" if raw_state == "exited" else raw_state
        if runtime_state not in RUNTIME_STATES:
            runtime_state = None
            gaps.append(name + ".runtime_state")
            partial_reason = partial_reason or "unsupported_runtime_state"

    created_at, gap = normalize_timestamp(item["created_at"])
    if gap:
        gaps.append(name + ".created_at")
    started_at, gap = normalize_timestamp(
        item["started_at"], semantic_zero_is_null=True
    )
    if gap:
        gaps.append(name + ".started_at")
    finished_at, gap = normalize_timestamp(
        item["finished_at"], semantic_zero_is_null=True
    )
    if gap:
        gaps.append(name + ".finished_at")
    restart_count, gap = _normalize_restart_count(item["restart_count"])
    if gap:
        gaps.append(name + ".restart_count")

    return {
        "name": name,
        "container_id": container_id,
        "full_image_reference": full_reference,
        "image_id": image_id,
        "runtime_state": runtime_state,
        "created_at": created_at,
        "started_at": started_at,
        "finished_at": finished_at,
        "restart_count": restart_count,
    }, gaps, partial_reason


def parse_inspect_chunk(data, requested_rows):
    """Parse one atomic chunk and retain valid field-local partial evidence."""

    expected = {row["container_id"]: row["name"] for row in requested_rows}
    parsed = {}
    for line in _decode_protocol_lines(data):
        try:
            item = _load_protocol_object(line)
        except (TypeError, ValueError, _DuplicateJsonKey):
            raise InspectFault("docker_protocol_error")
        if not isinstance(item, dict):
            raise InspectFault("docker_protocol_error")
        item_id = item.get("container_id")
        if not isinstance(item_id, str) or not CONTAINER_ID_RE.match(item_id):
            raise InspectFault("docker_protocol_error")
        if item_id not in expected or item_id in parsed:
            raise InspectFault("required_field_missing")
        parsed[item_id] = item
    if set(parsed) != set(expected):
        raise InspectFault("required_field_missing")

    containers = {}
    gaps = []
    partial_reason = None
    for row in requested_rows:
        try:
            normalized, item_gaps, item_reason = normalize_inspect_item(
                parsed[row["container_id"]], row["container_id"], row["name"]
            )
        except InspectFault as fault:
            if fault.gap:
                fault.gap = row["name"] + "." + fault.gap
            raise
        containers[normalized["name"]] = normalized
        gaps.extend(item_gaps)
        partial_reason = partial_reason or item_reason
    return containers, gaps, partial_reason


def classify_nonzero(stderr):
    lowered = stderr.lower()
    if (
        b"permission denied" in lowered
        or b"access denied" in lowered
        or b"unauthorized" in lowered
    ):
        return "docker_daemon_unauthorized"
    if (
        b"cannot connect to the docker daemon" in lowered
        or b"is the docker daemon running" in lowered
        or b"error during connect" in lowered
    ):
        return "docker_daemon_unreachable"
    return "docker_unavailable"


def _is_exact_no_such(stderr, requested_ids):
    if not stderr or not stderr.endswith(b"\n") or b"\r" in stderr:
        return False
    try:
        text = stderr.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return False
    lines = text[:-1].split("\n")
    if not lines:
        return False
    allowed = {"Error: No such object: " + identifier for identifier in requested_ids}
    return all(line in allowed for line in lines)


def _observation(scope, observed_at, observation_id, status, containers,
                 reason_code=None, metadata_gaps=None):
    warnings = [] if reason_code is None else [WARNING_BY_REASON[reason_code]]
    return {
        "observation_id": observation_id,
        "observed_at": observed_at,
        "scope": scope,
        "status": status,
        "reason_code": reason_code,
        "warnings": warnings,
        "discovery_backend": "docker_cli_v1",
        "metadata_gaps": sorted(set(metadata_gaps or []), key=lambda value: value.encode("ascii")),
        "containers": containers,
    }


def discover(
    scope,
    timeout_seconds,
    docker_path=_AUTO_DOCKER_PATH,
    runner=run_bounded_process,
    wall_clock=_utc_now,
    monotonic=time.monotonic,
    observation_id_factory=None,
):
    """Discover one bounded Docker observation.

    ``runner`` accepts ``(argv, timeout_seconds)`` and returns the safe mapping
    produced by :func:`run_bounded_process`. Tests can inject a deterministic
    fake runner without Docker.
    """

    observation_id_factory = observation_id_factory or (
        lambda: "obs-" + uuid.uuid4().hex
    )
    observation_id = observation_id_factory()
    if docker_path is _AUTO_DOCKER_PATH:
        docker_path = shutil.which("docker")
    observed_at = format_utc_timestamp(wall_clock())
    deadline = monotonic() + float(timeout_seconds)
    if not docker_path:
        return _observation(
            scope,
            observed_at,
            observation_id,
            "unavailable",
            None,
            "docker_cli_absent",
        )

    catalogue_argv = [
        docker_path,
        "container",
        "ls",
        "--all",
        "--no-trunc",
        "--format",
        CATALOGUE_FORMAT,
    ]
    remaining = max(0.0, deadline - monotonic())
    if remaining <= 0:
        return _observation(
            scope, observed_at, observation_id, "unavailable", None,
            "docker_command_timeout"
        )
    try:
        catalogue_result = runner(catalogue_argv, remaining)
    except OSError as error:
        reason = (
            "docker_cli_absent"
            if error.errno == errno.ENOENT
            else "docker_daemon_unauthorized"
            if error.errno in (errno.EACCES, errno.EPERM)
            else "docker_unavailable"
        )
        return _observation(
            scope, observed_at, observation_id, "unavailable", None, reason
        )
    if catalogue_result["status"] == "timeout":
        return _observation(
            scope, observed_at, observation_id, "unavailable", None,
            "docker_command_timeout"
        )
    if catalogue_result["status"] == "output_limit":
        return _observation(
            scope, observed_at, observation_id, "unavailable", None,
            "docker_output_limit_exceeded"
        )
    if catalogue_result["returncode"] != 0:
        return _observation(
            scope, observed_at, observation_id, "unavailable", None,
            classify_nonzero(catalogue_result["stderr"])
        )
    try:
        catalogue = parse_catalogue(catalogue_result["stdout"])
    except DiscoveryCapacityError:
        return _observation(
            scope, observed_at, observation_id, "unavailable", None,
            "discovery_capacity_exceeded"
        )
    except DiscoveryProtocolError:
        return _observation(
            scope, observed_at, observation_id, "unavailable", None,
            "docker_protocol_error"
        )

    gaps = []
    unknown_name = any(row["name"] is None for row in catalogue)
    if unknown_name:
        gaps.append("docker.catalogue")
    selected = [
        row for row in catalogue
        if row["name"] is not None and _scope_matches(row["name"], scope)
    ]
    containers = {}
    reason = "scope_membership_unknown" if unknown_name else None

    inspect_fixed = [
        docker_path,
        "container",
        "inspect",
        "--format",
        INSPECT_FORMAT,
    ]
    try:
        id_chunks = chunk_identifiers(
            inspect_fixed, [row["container_id"] for row in selected]
        )
    except InspectFault:
        gaps.extend(row["name"] + ".container_inspect" for row in selected)
        return _observation(
            scope, observed_at, observation_id, "partial", containers,
            reason or "inspect_identifier_argv_too_large", gaps
        )
    selected_by_id = {row["container_id"]: row for row in selected}

    for chunk_index, identifiers in enumerate(id_chunks):
        chunk_rows = [selected_by_id[identifier] for identifier in identifiers]
        remaining = max(0.0, deadline - monotonic())
        fault_reason = None
        fault_gap = None
        if remaining <= 0:
            fault_reason = "docker_command_timeout"
        else:
            try:
                result = runner(inspect_fixed + identifiers, remaining)
            except OSError as error:
                if error.errno in (
                    errno.EACCES,
                    errno.EPERM,
                ):
                    fault_reason = "docker_daemon_unauthorized"
                elif error.errno == errno.ENOENT:
                    fault_reason = "docker_cli_absent"
                else:
                    fault_reason = "docker_unavailable"
                result = None
            if result is None:
                pass
            elif result["status"] == "timeout":
                fault_reason = "docker_command_timeout"
            elif result["status"] == "output_limit":
                fault_reason = "docker_output_limit_exceeded"
            elif result["returncode"] != 0:
                if _is_exact_no_such(result["stderr"], identifiers):
                    fault_reason = "required_field_missing"
                else:
                    fault_reason = classify_nonzero(result["stderr"])
            else:
                try:
                    (
                        parsed_containers,
                        item_gaps,
                        item_reason,
                    ) = parse_inspect_chunk(
                        result["stdout"], chunk_rows
                    )
                    containers.update(parsed_containers)
                    gaps.extend(item_gaps)
                    reason = reason or item_reason
                    continue
                except InspectFault as fault:
                    fault_reason = fault.reason
                    fault_gap = fault.gap
                except DiscoveryProtocolError:
                    fault_reason = "docker_protocol_error"

        reason = reason or fault_reason
        if fault_gap:
            gaps.append(fault_gap)
        unresolved = []
        for later_ids in id_chunks[chunk_index:]:
            unresolved.extend(selected_by_id[identifier] for identifier in later_ids)
        gaps.extend(row["name"] + ".container_inspect" for row in unresolved)
        break

    status = "partial" if reason else "complete"
    return _observation(
        scope,
        observed_at,
        observation_id,
        status,
        containers,
        reason,
        gaps,
    )
