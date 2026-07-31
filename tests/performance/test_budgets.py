# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Offline synthetic performance regression guards for the DAS pure pipeline.

This is intentionally an in-process microbenchmark, not a Docker or Ansible
end-to-end benchmark.  Run it directly with ``--json`` to capture a
machine-readable result:

    python3 tests/performance/test_budgets.py --json

The timed interval covers raw inspect-item normalization, observation
validation, comparison, report-model construction, and ASCII rendering.
Synthetic workload construction and result verification are outside the timed
interval.
"""

from __future__ import absolute_import, division, print_function

import argparse
import gc
import json
import math
import os
import platform
import sys
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "module_utils"))

from docker_ansible_summary.compare import compare_observations  # noqa: E402
from docker_ansible_summary.discovery import (  # noqa: E402
    ARGV_MAX_BYTES,
    CONTAINER_CHUNK_MAX_ITEMS,
    normalize_inspect_item,
)
from docker_ansible_summary.render import render_report  # noqa: E402
from docker_ansible_summary.report import build_report_model  # noqa: E402
from docker_ansible_summary.validation import (  # noqa: E402
    normalize_scope,
    validate_observation,
)


BENCHMARK_SIZES = (0, 10, 100, 500, 1000)
COLD_REPETITIONS = 5
WARM_REPETITIONS = 20
REPORT_WIDTH = 120
FIVE_HUNDRED_LIMIT_MS = 100.0
ONE_THOUSAND_LIMIT_MS = 1000.0
GROWTH_FACTOR_LIMIT = 15.0


def _hex_identifier(value):
    return "{0:064x}".format(value)


def _raw_item(index, endpoint):
    name = "fixture-{0:04d}".format(index)
    container_id = _hex_identifier(index + 1)
    image_number = 10000 + index
    reference = "registry.example.test/das/app-{0:04d}:before".format(index)
    state = "running"
    started_at = "2026-07-30T12:00:01Z"
    restart_count = 0

    variant = index % 5
    if endpoint == "after":
        if variant == 1:
            image_number += 100000
            reference = "registry.example.test/das/app-{0:04d}:after".format(
                index
            )
        elif variant == 2:
            started_at = "2026-07-30T12:00:02Z"
            restart_count = 1
        elif variant == 3:
            state = "exited"
        elif variant == 4:
            container_id = _hex_identifier(index + 1000000)

    return {
        "container_id": container_id,
        "created_at": "2026-07-30T12:00:00.100000000Z",
        "finished_at": "0001-01-01T00:00:00Z",
        "full_image_reference": reference,
        "image_id": "sha256:" + _hex_identifier(image_number),
        "name": "/" + name,
        "restart_count": restart_count,
        "runtime_state": state,
        "started_at": started_at,
    }


def build_workload(object_count):
    """Build deterministic raw before/after inspect projections."""

    before = []
    after = []
    for index in range(object_count):
        before_item = _raw_item(index, "before")
        after_item = _raw_item(index, "after")
        name = "fixture-{0:04d}".format(index)
        before.append((before_item["container_id"], name, before_item))
        after.append((after_item["container_id"], name, after_item))
    return {"before": before, "after": after}


def _normalize_observation(raw_items, observation_id, observed_at, scope):
    containers = {}
    metadata_gaps = []
    for expected_id, expected_name, item in raw_items:
        container, gaps, partial_reason = normalize_inspect_item(
            item,
            expected_id=expected_id,
            expected_name=expected_name,
        )
        if partial_reason is not None:
            raise AssertionError(
                "complete benchmark projection became partial"
            )
        containers[expected_name] = container
        metadata_gaps.extend(gaps)

    observation = {
        "observation_id": observation_id,
        "observed_at": observed_at,
        "scope": scope,
        "status": "complete",
        "reason_code": None,
        "warnings": [],
        "discovery_backend": "docker_cli_v1",
        "metadata_gaps": sorted(metadata_gaps),
        "containers": containers,
    }
    validate_observation(observation, release=True)
    return observation


def run_pipeline(workload):
    """Run the complete pure benchmark pipeline once."""

    scope = normalize_scope("*")
    before = _normalize_observation(
        workload["before"],
        "benchmark-before",
        "2026-07-30T12:00:00Z",
        scope,
    )
    after = _normalize_observation(
        workload["after"],
        "benchmark-after",
        "2026-07-30T12:00:03Z",
        scope,
    )
    delta = compare_observations(before, after)
    machine_result = {
        "instance_id": "benchmark",
        "operation": "post",
        "correlation_id": "benchmark-offline",
        "simulated": False,
        "replay_outcome": None,
        "observation": after,
        "between_observation_delta": None,
        "run_window_delta": delta,
        "warnings": [],
        "baseline": {
            "advanced": True,
            "before": before["observation_id"],
            "after": after["observation_id"],
        },
        "journal_status": "complete",
        "persistence_outcome": "not_attempted",
    }
    report_model = build_report_model(
        machine_result,
        host="synthetic-benchmark.invalid",
        report_width=REPORT_WIDTH,
    )
    rendered = render_report(report_model, report_width=REPORT_WIDTH)
    return {
        "before": before,
        "after": after,
        "delta": delta,
        "report_model": report_model,
        "rendered": rendered,
    }


def _timed_pipeline(workload):
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        started = time.perf_counter()
        artifact = run_pipeline(workload)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
    finally:
        if gc_was_enabled:
            gc.enable()
    return elapsed_ms, artifact


def _nearest_rank(values, percentile):
    ordered = sorted(values)
    rank = max(1, int(math.ceil(percentile * len(ordered))))
    return ordered[rank - 1]


def _sample_summary(samples):
    return {
        "repetitions": len(samples),
        "p50_ms": _nearest_rank(samples, 0.50),
        "p95_ms": _nearest_rank(samples, 0.95),
        "min_ms": min(samples),
        "max_ms": max(samples),
    }


def _percentile_metadata(cold_repetitions, warm_repetitions):
    cold_p95_rank = max(
        1, int(math.ceil(0.95 * cold_repetitions))
    )
    warm_p95_rank = max(
        1, int(math.ceil(0.95 * warm_repetitions))
    )
    return {
        "method": "nearest_rank",
        "rank_rule": "ceil(percentile * sample_count)",
        "cold": {
            "sample_count": cold_repetitions,
            "p95_order_statistic": cold_p95_rank,
            "p95_is_maximum": cold_p95_rank == cold_repetitions,
            "use": "diagnostic_only",
        },
        "warm": {
            "sample_count": warm_repetitions,
            "p95_order_statistic": warm_p95_rank,
            "use": "local_regression_acceptance",
        },
        "scope": "local_regression_guard_not_portable_sla",
    }


def _verify_artifact(artifact, object_count):
    before = artifact["before"]
    after = artifact["after"]
    delta = artifact["delta"]
    model = artifact["report_model"]
    rendered = artifact["rendered"]

    if len(before["containers"]) != object_count:
        raise AssertionError("before observation object count mismatch")
    if len(after["containers"]) != object_count:
        raise AssertionError("after observation object count mismatch")
    if len(delta["changes"]) != object_count:
        raise AssertionError("comparison row count mismatch")
    if len(model["primary_table"]["rows"]) != object_count:
        raise AssertionError("report row count mismatch")
    if rendered.endswith("\n"):
        raise AssertionError("rendered report has a trailing newline")
    if "\x1b" in rendered:
        raise AssertionError("rendered report contains ANSI")
    if any(len(line) > REPORT_WIDTH for line in rendered.splitlines()):
        raise AssertionError("rendered report exceeds the configured width")

    if object_count:
        first = before["containers"]["fixture-0000"]
        if first["created_at"] != "2026-07-30T12:00:00.1Z":
            raise AssertionError("raw timestamp was not normalized")


def _total_memory_bytes():
    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        page_count = os.sysconf("SC_PHYS_PAGES")
    except (AttributeError, OSError, ValueError):
        return None
    if page_size <= 0 or page_count <= 0:
        return None
    return int(page_size) * int(page_count)


def _ansible_core_version():
    try:
        from ansible.release import __version__
    except Exception:
        return "not_importable"
    return str(__version__)


def environment_metadata():
    timer = time.get_clock_info("perf_counter")
    return {
        "ansible_core_version": _ansible_core_version(),
        "connection_mode": "none_in_process",
        "docker_version": "not_applicable_no_docker_invocation",
        "logical_cpu_count": os.cpu_count(),
        "machine": platform.machine() or "unknown",
        "operating_system": platform.system() or "unknown",
        "platform_release": platform.release() or "unknown",
        "processor": platform.processor() or "unknown",
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "timer": "perf_counter",
        "timer_monotonic": bool(timer.monotonic),
        "timer_resolution_seconds": timer.resolution,
        "total_memory_bytes": _total_memory_bytes(),
    }


def run_benchmark():
    """Run and return the complete JSON-serializable benchmark record."""

    results = []
    for object_count in BENCHMARK_SIZES:
        workload = build_workload(object_count)

        cold_samples = []
        artifact = None
        for _index in range(COLD_REPETITIONS):
            artifact = None
            gc.collect()
            elapsed_ms, artifact = _timed_pipeline(workload)
            cold_samples.append(elapsed_ms)

        # One unmeasured call establishes the explicitly process-local warm
        # state before consecutive timed repetitions.
        artifact = None
        run_pipeline(workload)
        warm_samples = []
        for _index in range(WARM_REPETITIONS):
            artifact = None
            elapsed_ms, artifact = _timed_pipeline(workload)
            warm_samples.append(elapsed_ms)

        _verify_artifact(artifact, object_count)
        results.append(
            {
                "object_count": object_count,
                "selected_container_count": object_count,
                "report_row_count": len(
                    artifact["report_model"]["primary_table"]["rows"]
                ),
                "rendered_utf8_bytes": len(
                    artifact["rendered"].encode("utf-8")
                ),
                "declared_docker_processes_if_live": (
                    1
                    + int(
                        math.ceil(
                            object_count
                            / float(CONTAINER_CHUNK_MAX_ITEMS)
                        )
                    )
                ),
                "actual_processes_invoked": 0,
                "cold_gc_conditioned": _sample_summary(cold_samples),
                "warm": _sample_summary(warm_samples),
            }
        )

    by_size = dict((item["object_count"], item) for item in results)
    p50_zero = by_size[0]["warm"]["p50_ms"]
    p50_hundred = by_size[100]["warm"]["p50_ms"]
    p50_thousand = by_size[1000]["warm"]["p50_ms"]
    denominator = p50_hundred - p50_zero
    numerator = p50_thousand - p50_zero
    resolution_ms = (
        time.get_clock_info("perf_counter").resolution * 1000.0
    )
    growth_is_measurable = (
        denominator > max(0.01, resolution_ms * 100.0)
        and numerator >= 0.0
    )
    growth_factor = (
        numerator / denominator if growth_is_measurable else None
    )

    guards = {
        "five_hundred_warm_p95": {
            "actual_ms": by_size[500]["warm"]["p95_ms"],
            "limit_ms_exclusive": FIVE_HUNDRED_LIMIT_MS,
            "passed": (
                by_size[500]["warm"]["p95_ms"]
                < FIVE_HUNDRED_LIMIT_MS
            ),
        },
        "one_thousand_warm_p95": {
            "actual_ms": by_size[1000]["warm"]["p95_ms"],
            "limit_ms_exclusive": ONE_THOUSAND_LIMIT_MS,
            "passed": (
                by_size[1000]["warm"]["p95_ms"]
                < ONE_THOUSAND_LIMIT_MS
            ),
        },
        "adjusted_p50_growth_100_to_1000": {
            "actual_factor": growth_factor,
            "fixed_startup_ms": p50_zero,
            "limit_factor_exclusive": GROWTH_FACTOR_LIMIT,
            "measurement_sound": growth_is_measurable,
            "passed": (
                None
                if not growth_is_measurable
                else growth_factor < GROWTH_FACTOR_LIMIT
            ),
        },
    }
    return {
        "benchmark_schema_version": 1,
        "benchmark_kind": "pure_synthetic_pipeline",
        "environment": environment_metadata(),
        "configuration": {
            "argv_max_bytes": ARGV_MAX_BYTES,
            "cold_definition": (
                "process-local full-GC-conditioned repetitions; imports and "
                "interpreter startup excluded"
            ),
            "cold_repetitions_per_size": COLD_REPETITIONS,
            "container_chunk_max_items": CONTAINER_CHUNK_MAX_ITEMS,
            "report_width": REPORT_WIDTH,
            "scope_pattern_bytes": 1,
            "scope_pattern_count": 1,
            "sizes": list(BENCHMARK_SIZES),
            "percentiles": _percentile_metadata(
                COLD_REPETITIONS, WARM_REPETITIONS
            ),
            "timed_stages": [
                "inspect_item_normalization",
                "observation_validation",
                "comparison",
                "report_model_construction",
                "ascii_rendering",
            ],
            "warm_definition": (
                "consecutive process-local repetitions after one unmeasured "
                "pipeline invocation"
            ),
            "warm_repetitions_per_size": WARM_REPETITIONS,
        },
        "guards": guards,
        "limitations": [
            (
                "Docker catalogue/inspect JSON parsing, subprocesses, and "
                "daemon latency are excluded"
            ),
            (
                "Ansible module transfer, connection, task, callback, and "
                "display latency are excluded"
            ),
            "state parsing, transition, locking, and persistence are excluded",
            (
                "cold samples are process-local GC-conditioned samples, not "
                "fresh-interpreter or cold-host samples"
            ),
            (
                "declared Docker process counts are arithmetic only; this "
                "pure benchmark invokes no processes"
            ),
            (
                "nearest-rank p95 over five cold samples is the fifth order "
                "statistic (the maximum) and is diagnostic only"
            ),
            (
                "warm acceptance uses twenty samples, whose nearest-rank "
                "p95 is the nineteenth order statistic"
            ),
            (
                "sample counts and thresholds are local regression guards, "
                "not statistically portable service-level objectives"
            ),
        ],
        "results": results,
    }


def assert_frozen_guards(record):
    guards = record["guards"]
    if not guards["five_hundred_warm_p95"]["passed"]:
        raise AssertionError(
            "500-object warm p95 exceeded the provisional 100 ms guard"
        )
    if not guards["one_thousand_warm_p95"]["passed"]:
        raise AssertionError(
            "1,000-object warm p95 exceeded the provisional one-second guard"
        )
    growth = guards["adjusted_p50_growth_100_to_1000"]
    if growth["measurement_sound"] and not growth["passed"]:
        raise AssertionError(
            "adjusted 100-to-1,000 p50 growth exceeded the 15-fold guard"
        )


class PerformanceBudgetTests(unittest.TestCase):
    def test_declared_process_event_output_and_timing_budgets(self):
        record = run_benchmark()
        self.assertEqual(
            list(BENCHMARK_SIZES),
            record["configuration"]["sizes"],
        )
        self.assertEqual(
            {
                "sample_count": 5,
                "p95_order_statistic": 5,
                "p95_is_maximum": True,
                "use": "diagnostic_only",
            },
            record["configuration"]["percentiles"]["cold"],
        )
        self.assertEqual(
            {
                "sample_count": 20,
                "p95_order_statistic": 19,
                "use": "local_regression_acceptance",
            },
            record["configuration"]["percentiles"]["warm"],
        )
        self.assertTrue(
            all(
                item["object_count"] == item["selected_container_count"]
                == item["report_row_count"]
                for item in record["results"]
            )
        )
        self.assertTrue(
            all(item["actual_processes_invoked"] == 0
                for item in record["results"])
        )
        self.assertEqual(
            [1, 2, 2, 6, 11],
            [
                item["declared_docker_processes_if_live"]
                for item in record["results"]
            ],
        )
        assert_frozen_guards(record)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json",
        action="store_true",
        help="print one benchmark record instead of running unittest",
    )
    arguments = parser.parse_args(argv)
    if arguments.json:
        record = run_benchmark()
        assert_frozen_guards(record)
        print(json.dumps(record, indent=2, sort_keys=True))
        return 0
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        PerformanceBudgetTests
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
