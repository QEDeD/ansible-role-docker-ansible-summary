<!--
SPDX-FileCopyrightText: 2026 QEDeD

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Docker Ansible Summary

Docker Ansible Summary (DAS) is a narrow, observation-only Ansible role. It
captures bounded Docker state before and after a caller-defined run window and
prints a concise table showing what was observed to change—or remain
unchanged.

```text
previous complete post A ── current pre B ── run window ── current post C
                       A → B                       B → C
```

`A → B` is a difference between observation endpoints. `B → C` is a
difference across the caller's run window. Neither comparison proves when,
why, or by whom a change was made.

The role:

- observes running and stopped containers within an explicit name scope;
- compares canonical image and runtime identity, not friendly version strings;
- keeps one bounded, versioned state store per caller-defined instance;
- returns one namespaced machine result;
- emits one final, host-identifiable ASCII report by default; and
- never starts, stops, restarts, creates, or removes Docker objects.

It does not record Ansible commands, Git state, controller output, arbitrary
Docker inspection data, or secrets. A run recorder can complement DAS through
an optional opaque correlation ID, but neither component depends on the other.

## Project status and ownership

This repository is a `LOCALLY_VALIDATED_CANDIDATE`, not a Gate-I-exit-ready
release. It is not a published release, a consumer integration, or a
production cutover. The exact evidence and remaining gaps are recorded in
[`docs/validation-status.md`](docs/validation-status.md).

QEDeD is the initial contributor owner and maintainer. A future transfer to
`mother-of-all-self-hosting/ansible-role-docker-ansible-summary` is an intended
governance outcome, not the current ownership state. Publishing the
contributor-owned development branch does not create a release, MASH adoption,
MDAD/MASH integration, or deployment; each remains a separate decision with
its own evidence.

A controlled consumer test may pin an exact contributor-branch commit, but it
must treat that revision as a pre-release candidate rather than a supported
role release.

## Requirements

The proposed compatibility targets are:

- Ansible Core 2.15.1 or newer;
- a Linux/POSIX managed node;
- managed-node Python 3.6 or newer; and
- Docker CLI 20.10.0 or newer with permission to query the daemon.

These are not current support claims. The repository metadata names Ansible
Core 2.20.1 because that is the lowest locally executed controller lane; its
exact development pin requires controller Python 3.12 or newer. Production
module sources parse with Python 3.6 grammar, but a Python 3.6 runtime lane has
not yet run. The role uses the Docker CLI and Python standard library; it does
not require the Docker Python SDK or `community.docker`. It does not force
privilege escalation.

## Public inputs

V1 accepts exactly the following 13 variables. Inputs shown as *omitted* are
intentionally absent from `defaults/main.yml`; defining them as null would
break omission-safe validation and the disabled short circuit.

<!-- public-inputs:start -->

| Variable | Default | Meaning |
|---|---:|---|
| `docker_ansible_summary_enabled` | `true` | Disable DAS without validating other inputs or touching Docker/filesystem state. |
| `docker_ansible_summary_operation` | *omitted; required when enabled* | `pre`, `post`, or `status`. |
| `docker_ansible_summary_instance_id` | *omitted; required when enabled* | Stable state-isolation and report label. |
| `docker_ansible_summary_scope` | *omitted; required when enabled* | Container-name glob, list of globs, `all`, or `*`. |
| `docker_ansible_summary_record_id` | *omitted* | Caller-supplied or prior `pre` record identifier; omission on `post` creates a post-only record. |
| `docker_ansible_summary_state_root` | `/var/lib/docker-ansible-summary` | Non-root absolute POSIX state root. |
| `docker_ansible_summary_journal_max_records` | `30` | Per-instance journal bound, from 1 through 100. |
| `docker_ansible_summary_state_max_bytes` | `16777216` | Per-instance state bound, from 1 MiB through 256 MiB. |
| `docker_ansible_summary_correlation_id` | *omitted* | Optional, bounded, non-secret caller grouping value. |
| `docker_ansible_summary_report_mode` | `final` | `final`, `each`, or `none`. |
| `docker_ansible_summary_report_width` | `120` | Deterministic report width, from 100 through 240. |
| `docker_ansible_summary_discovery_timeout_seconds` | `30` | One overall discovery deadline, from 1 through 300 seconds. |
| `docker_ansible_summary_failure_policy` | `report` | `report` or `fail_after_report`. |

<!-- public-inputs:end -->

Unknown `docker_ansible_summary_*` variables and removed predecessor variables
are rejected when the role is enabled. `docker_ansible_summary_enabled: false`
is validated first and needs no other input.

## Invocation

The reference path is a static repeated role import. It expands to one
role-owned task per phase and permits a host-local record identifier to flow
from `pre` to `post`:

```yaml
- name: DAS | Observe Docker state before the run
  ansible.builtin.import_role:
    name: docker_ansible_summary
    tasks_from: observe
    allow_duplicates: true
  vars:
    docker_ansible_summary_operation: pre
    docker_ansible_summary_instance_id: example
    docker_ansible_summary_scope:
      - example-*

# The caller's deployment tasks form the observation window.

- name: DAS | Observe Docker state after the run
  ansible.builtin.import_role:
    name: docker_ansible_summary
    tasks_from: observe
    allow_duplicates: true
  vars:
    docker_ansible_summary_operation: post
    docker_ansible_summary_instance_id: example
    docker_ansible_summary_scope:
      - example-*
    docker_ansible_summary_record_id: >-
      {{ docker_ansible_summary_result.record_id }}
```

Consumers that need best-effort post-capture after recoverable failures must
provide their own `block`/`always` orchestration. Controller loss,
unreachable hosts, and some fatal failures cannot be covered by role ordering.

Use `status` for a current, non-mutating observation:

```yaml
- name: DAS | Show current Docker state
  ansible.builtin.import_role:
    name: docker_ansible_summary
    tasks_from: observe
    allow_duplicates: true
  vars:
    docker_ansible_summary_operation: status
    docker_ansible_summary_instance_id: example
    docker_ansible_summary_scope: example-*
```

`status`, check mode, replay, conflict, and disabled paths do not write state.
Check mode still observes Docker and returns a simulated result.

## Result and reporting

The sole task registers `docker_ansible_summary_result`. Its stable v1 machine
surface contains:

```text
schema_version
operation
instance_id
record_id
correlation_id
observation
observation_status
scope_identity
between_observation_delta
run_window_delta
baseline
baseline_advanced
journal_status
persistence_outcome
replay_outcome
simulated
skipped
warnings
```

Keys that do not apply remain present as null. Successful task results report
`changed: false`, even when DAS atomically persists diagnostic evidence.
Failed calls return `changed: false`, `failed: true`, and one bounded
`docker_ansible_summary_failure` envelope rather than raw Docker output. Its
stable fields are:

```text
schema_version
host
instance_id
operation
record_id
observation_status
failure_reason
observation_reason
persistence_outcome
committed_result_replayable
replay_guidance
```

The replay fields distinguish a safe retained-result retry from a phase whose
commit outcome is uncertain. Ansible itself may add framework-owned callback
decoration such as `msg`; those keys are not part of the role-authored
envelope.

`report_mode: final` keeps a successful `pre` quiet and emits exactly one table
for a complete `post` or `status` observation. A partial or unavailable
observation emits a compact, value-safe warning block instead of a table.
`each` also reports `pre`; `none` suppresses informational presentation but
never hides required warnings or errors. Canonical machine values remain
complete even when table cells are shortened. Human table output is supported
only with Ansible's built-in default callback and linear strategy in v1.
Structured stdout callbacks have no separate human report transport and are
therefore unsupported; use `report_mode: none` when the callback stream must
remain machine-readable.

## Persistence and safety

Each instance has one canonical state namespace beneath
`docker_ansible_summary_state_root`. The implementation uses bounded retention,
optimistic revisions, a fixed lock timeout, and an atomic state-file
replacement. Only complete `post` observations may advance the baseline.
Partial or unavailable evidence cannot assert removals.

Persisted observations use a strict non-secret allowlist. DAS does not retain
environment values, labels, mounts, arbitrary inspect documents, command
output, controller paths, or inventory content.

The role has no legacy-import operation and never reads or writes the old
`matrix_*.fact` files. Legacy backup and cutover belong to a separately
authorized consumer integration.

## Development and testing

The minimal role-surface contract uses only Python's standard library and
works without installing dependencies:

```sh
python3 -m unittest discover -s tests/role_contract -p 'test_*.py'
```

The complete unit and frozen-fixture lane additionally needs PyYAML. After
creating the exact development environment below, run it with that
environment's interpreter:

```sh
PYTHONPATH=. .venv/bin/python \
  -m unittest discover -s tests/unit -p 'test_*.py'
.venv/bin/python tests/fixtures/conformance/validate.py
```

For the mandatory release-readiness Ansible, lint, Molecule, and REUSE lanes,
create an isolated environment and install the exact development-tool pins:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
```

Then run:

```sh
.venv/bin/yamllint .
.venv/bin/ansible-lint
.venv/bin/codespell .
PATH="$PWD/.venv/bin:$PATH" tests/ansible/run-local-contract.sh
PATH="$PWD/.venv/bin:$PATH" tests/ansible/run-multihost-record-handoff.sh
PATH="$PWD/.venv/bin:$PATH" tests/ansible/run-replay-contract.sh
PATH="$PWD/.venv/bin:$PATH" tests/callback/run-callback-contract.sh
PATH="$PWD/.venv/bin:$PATH" tests/callback/run-callback-failure-contract.sh
.venv/bin/molecule test
PYTHONPATH=. .venv/bin/python tests/performance/test_budgets.py --json
PYTHONPATH=. .venv/bin/python tests/performance/test_persistence_budgets.py
.venv/bin/reuse --no-multiprocessing lint
```

The structured-callback negative harness additionally requires the
`ansible.posix` collection. Point `ANSIBLE_COLLECTIONS_PATH` at an explicit
collection root containing `ansible_collections/ansible/posix`; the pip
requirements above do not install it. The harness exits with status 77 when
the callback is unavailable and never downloads a collection:

```sh
ANSIBLE_COLLECTIONS_PATH=/absolute/path/to/collection-root \
PATH="$PWD/.venv/bin:$PATH" \
tests/callback/run-structured-callback-contract.sh
```

This is a negative compatibility proof: it demonstrates why a DAS human
report is not valid structured callback stdout. It does not add structured
human-report support; select `report_mode: none` for structured stdout.

The standard-library contract suite validates the checked-in fake Docker CLI
directly. The Molecule scenario adds a local Ansible connection and executes
the role against that fake. Neither lane contacts a managed host, a Docker
daemon, or the network. Together they cover disabled, status, check-mode, and
repeated `pre`/`post` role calls.

Live-Docker tests are a separate opt-in lane. They must use a disposable local
daemon and preloaded or immutable pinned images; an ordinary test run must not
pull images or mutate a real deployment. Every live lane also requires the
guarded temporary root and exact sentinel described in
[`tests/live/README.md`](tests/live/README.md). The tests refuse default,
non-Unix, out-of-root, symlinked, or unsentinelled Docker endpoints:

```sh
DAS_LIVE_DOCKER=1 \
DAS_LIVE_DOCKER_ROOT=/tmp/path-to-disposable-root \
DOCKER_HOST=unix:///tmp/path-to-disposable-root/run/docker.sock \
PYTHONPATH=. \
.venv/bin/python -m unittest tests/live/test_docker_discovery.py -v

DAS_LIVE_DOCKER_MUTATING=1 \
DAS_LIVE_DOCKER_ROOT=/tmp/path-to-disposable-root \
DAS_LIVE_IMAGE_ID=sha256:<64-lowercase-hex> \
DAS_LIVE_IMAGE_ID_SECOND=sha256:<different-64-lowercase-hex> \
DOCKER_HOST=unix:///tmp/path-to-disposable-root/run/docker.sock \
PYTHONPATH=. \
.venv/bin/python -m unittest tests/live/test_docker_transition.py -v
```

## License

Copyright 2026 QEDeD.

Licensed under the
[GNU Affero General Public License v3.0 or later](LICENSE).
The repository follows the [REUSE](https://reuse.software/) specification.
