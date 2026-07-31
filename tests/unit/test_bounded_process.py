# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Real-process proofs for the bounded no-shell discovery runner."""

import os
import signal
import subprocess
import sys
import time
import unittest
from unittest import mock

from module_utils.docker_ansible_summary import discovery


class _CapturingPopen(object):
    def __init__(self):
        self.processes = []

    def __call__(self, *args, **kwargs):
        process = subprocess.Popen(*args, **kwargs)
        self.processes.append(process)
        return process


class BoundedProcessIntegrationTests(unittest.TestCase):
    def _run_child(self, source, timeout_seconds):
        factory = _CapturingPopen()
        self.addCleanup(self._force_cleanup, factory)
        started = time.monotonic()
        result = discovery.run_bounded_process(
            [sys.executable, "-I", "-c", source],
            timeout_seconds,
            popen_factory=factory,
        )
        elapsed = time.monotonic() - started

        self.assertEqual(1, len(factory.processes))
        process = factory.processes[0]
        self.assertIsNotNone(process.poll(), "the direct child was not reaped")
        self.assertEqual(process.returncode, process.wait(timeout=0.0))
        return result, process, elapsed

    @staticmethod
    def _force_cleanup(factory):
        for process in factory.processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2.0)

    def test_success_concurrently_drains_stdout_and_stderr(self):
        line_size = 1024
        repetitions = 60
        source = (
            "import os, threading\n"
            "def emit(fd, value):\n"
            "    line = value * 1023 + b'\\n'\n"
            "    for _ in range(60):\n"
            "        written = os.write(fd, line)\n"
            "        if written != len(line):\n"
            "            raise RuntimeError('partial pipe write')\n"
            "threads = [\n"
            "    threading.Thread(target=emit, args=(1, b'O')),\n"
            "    threading.Thread(target=emit, args=(2, b'E')),\n"
            "]\n"
            "for thread in threads:\n"
            "    thread.start()\n"
            "for thread in threads:\n"
            "    thread.join()\n"
        )

        result, _process, _elapsed = self._run_child(source, 5.0)

        self.assertEqual("ok", result["status"])
        self.assertEqual(0, result["returncode"])
        self.assertEqual(
            (b"O" * (line_size - 1) + b"\n") * repetitions,
            result["stdout"],
        )
        self.assertEqual(
            (b"E" * (line_size - 1) + b"\n") * repetitions,
            result["stderr"],
        )

    def test_nonzero_exit_preserves_return_code(self):
        source = (
            "import os\n"
            "os.write(1, b'bounded stdout\\n')\n"
            "os.write(2, b'bounded stderr\\n')\n"
            "raise SystemExit(23)\n"
        )

        result, _process, _elapsed = self._run_child(source, 5.0)

        self.assertEqual("ok", result["status"])
        self.assertEqual(23, result["returncode"])
        self.assertEqual(b"bounded stdout\n", result["stdout"])
        self.assertEqual(b"bounded stderr\n", result["stderr"])

    def test_stdout_cap_is_independent_and_reaps_child(self):
        source = (
            "import os, time\n"
            "os.write(2, b'stderr-safe\\n')\n"
            "time.sleep(0.05)\n"
            "os.write(1, b'x\\n' * 129)\n"
            "time.sleep(60)\n"
        )

        with mock.patch.object(discovery, "STDOUT_MAX_BYTES", 128):
            result, _process, _elapsed = self._run_child(source, 5.0)

        self.assertEqual("output_limit", result["status"])
        self.assertGreater(len(result["stdout"]), 128)
        self.assertEqual(b"stderr-safe\n", result["stderr"])
        self.assertIsNotNone(result["returncode"])

    def test_stderr_cap_is_independent_and_reaps_child(self):
        source = (
            "import os, time\n"
            "os.write(1, b'stdout-safe\\n')\n"
            "time.sleep(0.05)\n"
            "os.write(2, b'x\\n' * 129)\n"
            "time.sleep(60)\n"
        )

        with mock.patch.object(discovery, "STDERR_MAX_BYTES", 128):
            result, _process, _elapsed = self._run_child(source, 5.0)

        self.assertEqual("output_limit", result["status"])
        self.assertEqual(b"stdout-safe\n", result["stdout"])
        self.assertGreater(len(result["stderr"]), 128)
        self.assertIsNotNone(result["returncode"])

    def test_logical_line_cap_reaps_child(self):
        source = (
            "import os, time\n"
            "os.write(1, b'stdout-safe\\n')\n"
            "time.sleep(0.05)\n"
            "os.write(2, b'x' * 33 + b'\\n')\n"
            "time.sleep(60)\n"
        )

        with mock.patch.object(discovery, "OUTPUT_LINE_MAX_BYTES", 32):
            result, _process, _elapsed = self._run_child(source, 5.0)

        self.assertEqual("output_limit", result["status"])
        self.assertEqual(b"stdout-safe\n", result["stdout"])
        self.assertEqual(b"x" * 33 + b"\n", result["stderr"])
        self.assertIsNotNone(result["returncode"])

    @unittest.skipUnless(os.name == "posix", "requires POSIX process signals")
    def test_deadline_timeout_terminates_reaps_and_bounds_overrun(self):
        timeout_seconds = 0.20
        source = "import time\ntime.sleep(60)\n"

        result, _process, elapsed = self._run_child(source, timeout_seconds)

        self.assertEqual("timeout", result["status"])
        self.assertEqual(-signal.SIGTERM, result["returncode"])
        self.assertLessEqual(
            elapsed,
            timeout_seconds + 1.25,
            "deadline overrun exceeded termination and scheduling allowance",
        )

    @unittest.skipUnless(os.name == "posix", "requires POSIX process signals")
    def test_sigterm_resistant_child_is_killed_reaped_and_bounded(self):
        timeout_seconds = 0.75
        source = (
            "import os, signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "os.write(1, b'ready\\n')\n"
            "while True:\n"
            "    time.sleep(60)\n"
        )

        result, _process, elapsed = self._run_child(source, timeout_seconds)

        self.assertEqual("timeout", result["status"])
        self.assertEqual(b"ready\n", result["stdout"])
        self.assertEqual(-signal.SIGKILL, result["returncode"])
        self.assertLessEqual(
            elapsed,
            timeout_seconds + 1.50,
            "deadline overrun exceeded kill/reap and scheduling allowance",
        )


if __name__ == "__main__":
    unittest.main()
