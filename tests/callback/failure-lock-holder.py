#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 QEDeD
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Hold the real DAS stable lock until the callback harness terminates us."""

from __future__ import print_function

import argparse
import fcntl
import os
import signal
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", required=True)
    parser.add_argument("--ready", required=True)
    arguments = parser.parse_args()

    descriptor = os.open(arguments.lock, os.O_RDWR)
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    ready_descriptor = os.open(
        arguments.ready,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY,
        0o600,
    )
    os.close(ready_descriptor)

    def stop(_signal, _frame):
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
        sys.exit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while True:
        time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
