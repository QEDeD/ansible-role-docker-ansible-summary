<!--
SPDX-FileCopyrightText: 2026 QEDeD

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Molecule scenarios

## `default` (daemonless)

The default scenario runs against a local Ansible connection and
places a deterministic fake `docker` executable first in the managed task's
`PATH`. It exercises the role boundary without a container driver, Docker
daemon, network access, privilege escalation, or managed host.

The scenario covers:

- an omission-safe disabled invocation;
- a non-mutating `status` invocation;
- a check-mode `pre` observation with no state write;
- two static imports with a host-local `record_id` hand-off; and
- the one-catalogue-plus-one-inspect process shape for one selected container.

Run it from the repository root:

```sh
.venv/bin/molecule test
```

Live-Docker behavior belongs in the separate opt-in direct-test lane under
`tests/live/`. It requires the documented guarded disposable daemon and never
pulls an image.
