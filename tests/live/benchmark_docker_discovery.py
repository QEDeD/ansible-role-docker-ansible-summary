# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Measure discovery against an explicitly selected disposable Docker daemon."""

from __future__ import absolute_import, division, print_function

import argparse
import gc
import json
import math
import os
import platform
import subprocess
import time

from module_utils.docker_ansible_summary.discovery import (
    CONTAINER_CHUNK_MAX_ITEMS,
    discover,
    run_bounded_process,
)
from module_utils.docker_ansible_summary.validation import (
    normalize_scope,
    validate_observation,
)
from tests.live.docker_safety import require_disposable_docker_host


def _nearest_rank(values, percentile):
    ordered = sorted(values)
    rank = max(1, int(math.ceil(percentile * len(ordered))))
    return ordered[rank - 1]


def _summary(samples):
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
            "use": "local_regression_evidence",
        },
        "scope": "local_regression_guard_not_portable_sla",
    }


class _CountingRunner(object):
    def __init__(self):
        self.calls = 0

    def __call__(self, argv, timeout_seconds):
        self.calls += 1
        return run_bounded_process(argv, timeout_seconds)


def _sample(scope, expected_count, docker_path):
    runner = _CountingRunner()
    started = time.perf_counter()
    observation = discover(
        scope,
        timeout_seconds=30,
        docker_path=docker_path,
        runner=runner,
    )
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    validate_observation(observation, release=True)
    if observation["status"] != "complete":
        raise AssertionError(
            "live discovery was not complete: %s"
            % observation["reason_code"]
        )
    if len(observation["containers"]) != expected_count:
        raise AssertionError("selected-container count mismatch")
    expected_processes = 1 + int(
        math.ceil(
            expected_count / float(CONTAINER_CHUNK_MAX_ITEMS)
        )
    )
    if runner.calls != expected_processes:
        raise AssertionError("Docker process-count formula mismatch")
    return elapsed_ms, runner.calls


def run_benchmark(scope_value, expected_count, cold_repetitions, warm_repetitions):
    docker_path, _socket_path, _root = require_disposable_docker_host(
        "DAS_LIVE_DOCKER_BENCHMARK"
    )

    scope = normalize_scope(scope_value)
    cold_samples = []
    process_count = None
    for _index in range(cold_repetitions):
        gc.collect()
        elapsed, process_count = _sample(
            scope, expected_count, docker_path
        )
        cold_samples.append(elapsed)

    _sample(scope, expected_count, docker_path)
    warm_samples = []
    for _index in range(warm_repetitions):
        elapsed, process_count = _sample(
            scope, expected_count, docker_path
        )
        warm_samples.append(elapsed)

    docker_version = subprocess.check_output(
        [docker_path, "version", "--format", "{{.Server.Version}}"],
        stderr=subprocess.DEVNULL,
    ).decode("ascii").strip()
    return {
        "benchmark_schema_version": 1,
        "benchmark_kind": "disposable_docker_discovery",
        "environment": {
            "connection_mode": "local_unix_socket",
            "docker_host": "explicit_disposable_unix_socket",
            "docker_version": docker_version,
            "logical_cpu_count": os.cpu_count(),
            "machine": platform.machine() or "unknown",
            "operating_system": platform.system() or "unknown",
            "python_version": platform.python_version(),
        },
        "configuration": {
            "cold_definition": (
                "consecutive daemon calls with process-local full GC; "
                "host and daemon caches are not flushed"
            ),
            "cold_repetitions": cold_repetitions,
            "percentiles": _percentile_metadata(
                cold_repetitions, warm_repetitions
            ),
            "scope": scope["patterns"],
            "selected_container_count": expected_count,
            "warm_definition": (
                "consecutive calls after one unmeasured discovery"
            ),
            "warm_repetitions": warm_repetitions,
        },
        "docker_processes_per_discovery": process_count,
        "cold_gc_conditioned": _summary(cold_samples),
        "warm": _summary(warm_samples),
        "limitations": [
            "not a fresh-host or cache-flushed cold benchmark",
            "excludes Ansible transport, callbacks, rendering, and persistence",
            (
                "nearest-rank p95 over the default five cold samples is the "
                "fifth order statistic (the maximum) and is diagnostic only"
            ),
            (
                "the default warm evidence uses twenty samples, whose "
                "nearest-rank p95 is the nineteenth order statistic"
            ),
            (
                "sample counts and timings are local regression evidence, "
                "not statistically portable service-level objectives"
            ),
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope", required=True)
    parser.add_argument("--expected-count", required=True, type=int)
    parser.add_argument("--cold-repetitions", type=int, default=5)
    parser.add_argument("--warm-repetitions", type=int, default=20)
    arguments = parser.parse_args()
    result = run_benchmark(
        arguments.scope,
        arguments.expected_count,
        arguments.cold_repetitions,
        arguments.warm_repetitions,
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
