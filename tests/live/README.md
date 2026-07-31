<!--
SPDX-FileCopyrightText: 2026 QEDeD

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Opt-in live-Docker tests

These tests are deliberately outside the normal offline suite. They never
select Docker's default context and they never pull an image. The caller must
start an isolated disposable local daemon, preload its images, and explicitly
identify its Unix socket.

All three live lanes require:

- `DOCKER_HOST=unix:///absolute/path/to/docker.sock`;
- `DAS_LIVE_DOCKER_ROOT` set to a non-symlink directory below the system
  temporary directory which contains that socket;
- a regular, non-symlink
  `$DAS_LIVE_DOCKER_ROOT/.das-live-disposable-daemon` file containing exactly
  `docker-ansible-summary disposable live daemon v1` plus one newline; and
- a Docker CLI on `PATH`.

For example, after the operator has created and started a disposable daemon:

```sh
export DAS_LIVE_DOCKER_ROOT=/tmp/das-disposable-example
export DOCKER_HOST=unix:///tmp/das-disposable-example/run/docker.sock
printf '%s\n' \
  'docker-ansible-summary disposable live daemon v1' \
  >"$DAS_LIVE_DOCKER_ROOT/.das-live-disposable-daemon"
```

The guard rejects TCP endpoints, known system sockets, sockets outside the
declared temporary root, a missing or altered sentinel, symlinked roots and
sentinels, and non-socket endpoints. The sentinel is a deliberate operator
acknowledgement, not a cryptographic proof; never create it for a normal
operator daemon.

## Read-only discovery

```sh
DAS_LIVE_DOCKER=1 \
DAS_LIVE_SCOPE='das-live-*' \
PYTHONPATH=. \
.venv/bin/python -m unittest tests/live/test_docker_discovery.py -v
```

`DAS_LIVE_EXPECTED_NAMES` may contain a comma-separated exact expected set.

## Lifecycle matrix

Preload an image and pass its exact local `sha256:<64 lowercase hex>` image ID:

```sh
DAS_LIVE_DOCKER_MUTATING=1 \
DAS_LIVE_IMAGE_ID=sha256:... \
PYTHONPATH=. \
.venv/bin/python -m unittest tests/live/test_docker_transition.py -v
```

Every supplied image must provide `sh` and `sleep`; containers run the fixed
offline command `sh -c 'while :; do sleep 3600; done'`. The test passes
`--pull=never`, creates uniquely prefixed containers, verifies that the prefix
was initially empty, labels each container, and removes only the exact full
container IDs it created.

The core lane covers an authoritative complete-empty catalogue, simultaneous
running and stopped catalogue rows, stopped-to-running, running-to-stopped,
restart, same-image recreation, addition, removal, all-removals, and a final
complete-empty catalogue. It also renders the all-removals table.

Set `DAS_LIVE_IMAGE_ID_SECOND` to a distinct, already-loaded exact image ID to
enable the same-tag/new-image-ID lane. That lane first proves the unique tag
does not exist, creates it, repoints it locally, proves unchanged configured
reference plus changed image ID, then removes only that tag. Each source image
must retain at least one pre-existing tag so removing the test tag cannot
delete a previously dangling image. The lane is skipped when a second image is
not provided, the two IDs resolve to equal content, or either image lacks such
a tag.

The daemon-denial lane creates a mode-`000` Unix socket beneath the disposable
root and expects `docker_daemon_unauthorized`. It is skipped for effective UID
0, whose permission bypass makes this fixture unable to prove denial. It does
not change the disposable daemon socket.

Cleanup is attempted even after an assertion fails. A cleanup failure fails an
otherwise successful test and is reported as a warning when preserving an
earlier failure. The suite never creates, starts, stops, or removes the daemon
itself.

## Discovery benchmark

The benchmark is read-only, but still requires the same disposable-root and
sentinel guard:

```sh
DAS_LIVE_DOCKER_BENCHMARK=1 \
PYTHONPATH=. \
.venv/bin/python tests/live/benchmark_docker_discovery.py \
  --scope 'das-benchmark-*' \
  --expected-count 100
```

Container creation for a benchmark is intentionally outside the benchmark
script. Exact selected-container counts, host/daemon cache state, rootless
storage drivers, and concurrent daemon work can materially affect timing.
