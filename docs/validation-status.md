<!--
SPDX-FileCopyrightText: 2026 QEDeD

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Validation status

## Classification

The exact local handoff tree is classified
`LOCALLY_VALIDATED_CANDIDATE`. This document distinguishes completed local
evidence from support-matrix and external proofs that remain unavailable. No
publication, integration, deployment, or production-support claim follows
from this classification.

The permitted final classifications are:

- `LOCALLY_VALIDATED_CANDIDATE`: every mandatory offline and authorized local
  lane passes, while unavailable support-matrix or external proofs remain
  explicit.
- `GATE_I_EXIT_READY`: every frozen Gate-I proof passes on the claimed support
  matrix and representative release environment.

The current evidence supports `LOCALLY_VALIDATED_CANDIDATE`, not
`GATE_I_EXIT_READY`. Ansible Core 2.15.1, a managed-node Python 3.6 runtime,
Docker CLI 20.10.0, and a wider platform matrix have not been executed.

## Contract provenance

The normative v1 contract is the frozen planning package in the MDAD
deployment fork. It was frozen at this commit on the fork's original
planning branch `deployment/das-rewrite-planning`; since the fork's
2026-08-04 branch-topology migration, the package lives on
`downstream/das-rewrite-planning`:

```text
32c7c106fe1b7f6a126f094774cb5531f44fb0e4
plans: freeze DAS rewrite implementation contract
```

The implementation repository contains a copied, implementation-independent
conformance corpus with its source provenance recorded in
[`tests/fixtures/conformance/PROVENANCE.md`](../tests/fixtures/conformance/PROVENANCE.md).
Three internally contradictory oracle details were corrected after the freeze
commit. The byte-pressure case's aliased pre-observation and journal-record
timestamps now refer to the same endpoint and its canonical hashes were
recomputed. The missing-input execution case now expects the one value-free
controller diagnostic required by the specification and presentation fixture,
rather than zero display calls. The inspect-name-mismatch case now records the
whole invalid inspect chunk plus the mismatched name gap, matching the
specification's atomic identity rule. The validators were also hardened to use
absolute regular-expression anchors without changing an oracle. The normative
planning branch and this copy contain all corrections; the planning ledger
records their exact post-freeze history.

## Reference environment

Unless a row states otherwise, local evidence was collected on:

| Component | Observed value |
|---|---|
| Kernel/platform | Linux 7.0.0-28-generic, x86_64 |
| Logical CPUs | 4 |
| Memory reported to the benchmark | 5,663,744,000 bytes |
| Controller Python | CPython 3.14.4 |
| Ansible Core | 2.20.1 |
| Molecule | 26.6.0, `default` driver and local connection |
| Docker CLI/daemon | 29.1.3, isolated rootless daemon, `vfs` storage driver |
| Callback/strategy | built-in `default`, `linear` |

Development tools are exactly pinned in
[`requirements-dev.txt`](../requirements-dev.txt). The Ansible-based local
lanes use isolated temporary Ansible and cache directories.

## Verification ledger

| Proof lane | Result | Scope |
|---|---|---|
| Frozen fixture validator | Passed | 35 fixtures: 22 numbered, 5 legacy, 8 focused |
| Pure, adapter, persistence, renderer, action, and conformance-binding unit tests | Passed | 209 tests; production functions, fake process transcripts, real temporary filesystem |
| Minimal role-source contract | Passed | 11 tests; public/default surface, static task boundary, source safety |
| Direct local Ansible role contract | Passed | Disabled, status, check mode, final table, and bounded invalid input |
| Two-host Ansible record handoff | Passed | 2 role tasks, 4 host results, 4 module calls, 8 Docker processes |
| Retained-result replay | Passed | 3 role calls; replay made no Docker call or persistence write and retained identical state bytes/metadata |
| Molecule `default` scenario | Passed | All 9 stages; local connection and fake Docker, no daemon/network |
| Callback success matrix | Passed | YAML/JSON result formats, color off/on, 2 hosts, 4 forks |
| Expected-failure callback matrix | Passed | 44 lanes: 11 cases × YAML/JSON × color off/on; 12 state postconditions |
| Structured-callback negative lane | Passed | `ansible.posix` 2.1.0; human reporting proved to invalidate whole-stdout JSON |
| Pure pipeline benchmark | Passed | 0/10/100/500/1000 selected-container profiles |
| Real-filesystem persistence benchmark | Passed | Complete-empty, typical, and near-default-byte-ceiling profiles |
| Live Docker behavior | Passed | Disposable rootless daemon; 4 tests |
| Live Docker discovery benchmark | Passed | 0/10/100 selected containers |
| YAML, Ansible, spelling, and REUSE lint | Passed | 124 Ansible-lint files; 143/143 REUSE files; spelling clean; frozen-oracle YAML line-length warnings only |
| Python 3.6 grammar parse | Passed | All 16 production Python sources; not a runtime claim |

Ordinary unit discovery does not opt into live Docker. The live tests require
the multi-part disposable-daemon guard documented in
[`tests/live/README.md`](../tests/live/README.md).

## Implementation proof map

The frozen conformance document names proof responsibilities using
pre-implementation placeholder paths. The authoritative implementation-name
update is [`tests/proof-registry.yml`](../tests/proof-registry.yml). A unit
test verifies that the registry owns exactly `DAS-R001` through `DAS-R020`,
includes every mandatory secondary lane, and names only existing executable
paths/selectors. That structural check does not execute the registered lanes;
their results are recorded separately in the verification ledger. The
registry's domains compress to:

| Contract domain | Implementation-bound proof |
|---|---|
| Corpus structure and cross-case semantics | `tests/fixtures/conformance/validate.py` |
| Numbered comparison scenarios 1–18 and change kinds | `tests/unit/test_comparison.py` |
| Numbered isolation/status/conflict scenarios 19–21 and normalization | `tests/unit/test_conformance_binding.py` |
| Operation/lifecycle matrix | `tests/unit/test_operation_contract_binding.py` |
| Persistence, retention, replay, corruption, faults, and namespace safety | `tests/unit/test_persistence_fixture_contract.py` plus `test_persistence.py` |
| Task/process/result/report-mode execution surface | `tests/unit/test_execution_surface_fixture_binding.py` |
| Image parsing and collision-safe projection | `tests/unit/test_image.py` |
| ReportModel and exact renderer goldens | `tests/unit/test_report.py` and `test_render.py` |
| Action/module and bounded failure boundary | `tests/unit/test_action_plugin.py`, direct Ansible harnesses, and callback harnesses |
| Public role/YAML/metadata boundary | `tests/role_contract/test_role_contract.py` |
| Performance | `tests/performance/` and `tests/live/benchmark_docker_discovery.py` |
| Disposable-daemon behavior | `tests/live/test_docker_discovery.py` and `test_docker_transition.py` |

Scenario 22 and the focused legacy-boundary cases describe a future
MDAD-owned cutover assessment. The standalone role's Gate-I obligation is the
negative boundary: it has no legacy operation, path, input, or state import.

## Measured execution and output surface

The successful callback matrix produced, in each of four
format/color combinations:

- 2 total task-start events: 1 role-owned observation and 1 harness assertion;
- 4 successful host result events;
- exactly 2 complete 11-line DAS reports; and
- no ANSI bytes inside either report, duplication, interleaving, or cross-host
  contamination.

The expected-failure callback matrix passed all 44 combinations of 11 cases,
two result formats, and two color modes. Eight cases exercised
production-triggerable boundaries: unavailable Docker, invalid input, unsafe
state namespace, corrupt state, state size, lock timeout, revision conflict,
and presentation capacity. Three deterministic harness seams injected
before-replace write failure, after-replace/before-directory-`fsync` failure,
and post-commit render failure. Every lane produced one bounded terminal
failure, the required diagnostic-before-failure order, and no item-result
noise; 12 associated state checks also passed.

The structured-callback negative lane used `ansible.posix` 2.1.0. It observed
two callback tasks and 17 callback-visible machine fields, while the 11-line
human report made the complete stdout stream invalid JSON. This confirms the
documented `report_mode: none` boundary rather than structured human-report
support.

The direct local contract reported `ok=14`, `changed=0`, `skipped=1`, and
`rescued=1`, with six bounded fake-Docker calls. The separate two-host
handoff lane reported `role_tasks=2`, `harness_tasks=8`,
`role_host_results=4`, `module_invocations=4`, and `docker_processes=8`.
The replay lane reported three role/module invocations and four initial Docker
processes; its retained replay made zero Docker calls and zero persistence
writes while preserving state bytes and persistence metadata exactly.

Molecule's converge play reported `ok=18`, `changed=0`, and `skipped=1`.
Its fake-Docker ledger contained eight calls across the exercised phases.
Status and check mode created no state, while the repeated pre/post path
created its expected bounded state.

The implementation's discovery process formula is one catalogue invocation
plus deterministic selected-container inspect chunks. There are no per-object
Ansible tasks or presentation-only Docker queries.

## Performance evidence

These timings are local regression evidence, not portable service-level
claims.

All reported percentiles use the nearest-rank rule
`ceil(percentile × sample count)`. With five cold samples, p95 is therefore
the fifth order statistic—the maximum observed value—and is diagnostic only.
The local acceptance guards use twenty warm samples, for which p95 is the
nineteenth order statistic. Twenty observations are sufficient to make that
nearest-rank position distinct from the maximum, but they do not establish a
portable tail-latency distribution or service-level objective. The live
Docker p95 values are evidence only; they are not acceptance thresholds.

### Pure pipeline

Five cold and twenty warm repetitions were run per profile. Times are
milliseconds:

| Selected containers | Cold p50 | Cold p95 | Warm p50 | Warm p95 |
|---:|---:|---:|---:|---:|
| 0 | 0.303 | 0.431 | 0.192 | 0.200 |
| 10 | 1.556 | 3.943 | 1.384 | 1.393 |
| 100 | 11.557 | 11.817 | 11.813 | 12.070 |
| 500 | 58.236 | 59.455 | 56.153 | 57.093 |
| 1,000 | 115.177 | 118.570 | 124.613 | 138.087 |

Fixed-cost-adjusted warm growth from 100 to 1,000 containers was `10.707x`,
within the frozen `<15x` regression guard.

### Real-filesystem persistence

Each sample used a fresh secure namespace and the production store, including
canonical decode/encode, retention, locking, file and directory `fsync`,
same-directory atomic replacement, and reload:

| Profile | Records × containers | Bytes | Cold total p50/p95 (ms) | Warm total p50/p95 (ms) |
|---|---:|---:|---:|---:|
| Complete empty | 1 × 0 | 1,295 | 1.539 / 1.624 | 1.245 / 1.699 |
| Typical | 5 × 10 | 29,121 | 10.561 / 10.646 | 10.044 / 10.961 |
| Near byte ceiling | 30 × 1,000 | 12,728,583 | 3,601.221 / 3,655.477 | 3,642.497 / 3,834.979 |

The near-cap fixture occupied `75.87%` of the default 16 MiB bound. Its warm
total p95 passed the predeclared 10-second local guard; the typical warm p95
passed the 2-second guard.

### Disposable live Docker discovery

Five cold and twenty warm repetitions used the isolated rootless daemon:

| Selected containers | Docker processes | Cold p50/p95 (ms) | Warm p50/p95 (ms) |
|---:|---:|---:|---:|
| 0 | 1 | 23.580 / 24.934 | 22.034 / 23.726 |
| 10 | 2 | 47.206 / 84.391 | 45.370 / 61.292 |
| 100 | 2 | 120.506 / 139.632 | 120.580 / 156.840 |

The live lifecycle suite covered authoritative empty, simultaneous running
and stopped containers, start, stop, restart, recreation, addition, removal,
all-removals with table rendering, same configured tag with a changed image
ID, and daemon permission denial. Test containers used `--network none` and
`--pull=never`. All exact test objects, images, daemon state, and daemon roots
were removed after the run. The four tests passed without skips in 5.827
seconds. The benchmark used stopped containers and did not flush host or
daemon caches.

## Known limits and remaining Gate-I proofs

- The proposed Ansible Core 2.15.1 floor is untested; metadata therefore names
  2.20.1, the lowest executed lane.
- Python 3.6 grammar compatibility is checked, but no managed-node Python 3.6
  runtime lane has executed.
- Docker CLI 20.10.0 and a broader daemon/platform matrix have not executed.
- Human reports support only the built-in default callback with linear
  strategy. Structured stdout callbacks are not a report transport; use
  `report_mode: none`.
- The performance figures describe one local four-CPU environment. The pure
  and persistence budgets are regression guards; a release policy still needs
  representative support-matrix evidence.
- Last-resort exception boundaries deliberately fail closed, but an
  unexpected module exception may use `state_write_failed`, and malformed
  module output may use `render_failed`. Introducing fully specific internal
  or module-contract labels requires a future versioned failure-code change.
- No CI, immutable release tag, MDAD/MASH adapter, adoption, deployment, or
  production cutover exists. A published contributor branch remains
  pre-release source and does not close these gaps.

### Unexecuted Gate-I command templates

None of the commands in this section has been executed as evidence. They are
reproducible templates for closing the named gaps on disposable local or CI
test systems. They must be run from the role repository, must not target a
deployment, and must retain their complete environment metadata and output.

#### Ansible Core 2.15.1 controller

Use a CPython 3.11 controller so that the controller interpreter itself is
inside Ansible Core 2.15's supported range. Create an independent environment;
do not replace the repository's currently evidenced 2.20.1 environment:

```sh
DAS_GATE_ANSIBLE_ROOT=$(mktemp -d /tmp/das-gate-ansible-2.15.1.XXXXXX)
python3.11 -m venv "$DAS_GATE_ANSIBLE_ROOT/venv"
"$DAS_GATE_ANSIBLE_ROOT/venv/bin/pip" install \
  'ansible-core==2.15.1' \
  'PyYAML==6.0.3'
"$DAS_GATE_ANSIBLE_ROOT/venv/bin/python" --version
"$DAS_GATE_ANSIBLE_ROOT/venv/bin/ansible" --version
PYTHONPATH=. \
  "$DAS_GATE_ANSIBLE_ROOT/venv/bin/python" \
  -m unittest discover -s tests/unit -p 'test_*.py'
PATH="$DAS_GATE_ANSIBLE_ROOT/venv/bin:$PATH" \
  tests/ansible/run-local-contract.sh
PATH="$DAS_GATE_ANSIBLE_ROOT/venv/bin:$PATH" \
  tests/ansible/run-multihost-record-handoff.sh
PATH="$DAS_GATE_ANSIBLE_ROOT/venv/bin:$PATH" \
  tests/ansible/run-replay-contract.sh
PATH="$DAS_GATE_ANSIBLE_ROOT/venv/bin:$PATH" \
  tests/callback/run-callback-contract.sh
PATH="$DAS_GATE_ANSIBLE_ROOT/venv/bin:$PATH" \
  tests/callback/run-callback-failure-contract.sh
```

The structured-callback negative lane additionally needs an explicitly pinned
`ansible.posix` collection root. For example, after independently obtaining
`ansible.posix` 2.1.0 beneath
`$DAS_GATE_ANSIBLE_ROOT/collections/ansible_collections/ansible/posix`:

```sh
ANSIBLE_COLLECTIONS_PATH="$DAS_GATE_ANSIBLE_ROOT/collections" \
PATH="$DAS_GATE_ANSIBLE_ROOT/venv/bin:$PATH" \
  tests/callback/run-structured-callback-contract.sh
```

The collection must be supplied before the run; the harness deliberately
does not download it. Preserve `pip freeze`, the collection manifest, all test
output, and the exit status. Only a completely passing lane would justify
lowering `meta/main.yml` from the executed 2.20.1 floor.

#### Managed-node Python 3.6 runtime

Grammar parsing is not runtime evidence. Point the Ansible 2.15.1 environment
above at a real CPython 3.6 interpreter on an isolated local test target. The
environment setting affects managed-module execution, while the action plugin
continues to execute on the controller:

```sh
DAS_GATE_PY36=/absolute/path/to/python3.6
test "$("$DAS_GATE_PY36" -c \
  'import sys; print(".".join(map(str, sys.version_info[:2])))')" = 3.6
ANSIBLE_PYTHON_INTERPRETER="$DAS_GATE_PY36" \
PATH="$DAS_GATE_ANSIBLE_ROOT/venv/bin:$PATH" \
  tests/ansible/run-local-contract.sh
ANSIBLE_PYTHON_INTERPRETER="$DAS_GATE_PY36" \
PATH="$DAS_GATE_ANSIBLE_ROOT/venv/bin:$PATH" \
  tests/ansible/run-multihost-record-handoff.sh
ANSIBLE_PYTHON_INTERPRETER="$DAS_GATE_PY36" \
PATH="$DAS_GATE_ANSIBLE_ROOT/venv/bin:$PATH" \
  tests/ansible/run-replay-contract.sh
```

Capture the exact `python3.6 --version`, operating system, architecture,
filesystem, controller version, play recap, fake-Docker ledger, and callback
output. A passing grammar check or a controller-side unit run cannot replace
this managed-module lane.

#### Docker CLI and daemon 20.10.0

Provision a disposable daemon and preloaded local test images exactly as
described in [`tests/live/README.md`](../tests/live/README.md), then prove both
the selected client and server are 20.10.0 before opting in:

```sh
test "$(docker version --format \
  '{{.Client.Version}}/{{.Server.Version}}')" = '20.10.0/20.10.0'
DAS_LIVE_DOCKER=1 \
PYTHONPATH=. \
  python3 -m unittest tests/live/test_docker_discovery.py -v
DAS_LIVE_DOCKER_MUTATING=1 \
DAS_LIVE_IMAGE_ID="$DAS_GATE_IMAGE_ID" \
DAS_LIVE_IMAGE_ID_SECOND="$DAS_GATE_IMAGE_ID_SECOND" \
PYTHONPATH=. \
  python3 -m unittest tests/live/test_docker_transition.py -v
DAS_LIVE_DOCKER_BENCHMARK=1 \
PYTHONPATH=. \
  python3 tests/live/benchmark_docker_discovery.py \
  --scope 'das-benchmark-*' \
  --expected-count 0
```

`DOCKER_HOST`, `DAS_LIVE_DOCKER_ROOT`, the exact sentinel, and the two
preloaded image-ID variables are prerequisites from the live-test guide.
Record client and server versions, daemon mode, storage driver, cgroup mode,
architecture, selected-container counts, benchmark JSON, and cleanup result.
Evidence from a newer client against an older server, or the reverse, does not
prove this exact floor.

#### Broader platform matrix

The intended support cells must be declared before running them; an
unspecified collection of convenient hosts cannot establish a support claim.
At minimum, each proposed operating-system/architecture cell must identify its
controller Python and Ansible versions, managed Python, Docker client and
server versions, daemon privilege mode, storage driver, cgroup mode, kernel,
CPU count, and filesystem. On every isolated matrix runner, execute:

```sh
uname -a
"$PWD/.venv/bin/python" --version
"$PWD/.venv/bin/ansible" --version
docker version
docker info
PYTHONPATH=. "$PWD/.venv/bin/python" \
  -m unittest discover -s tests/unit -p 'test_*.py'
"$PWD/.venv/bin/python" \
  -m unittest discover -s tests/role_contract -p 'test_*.py'
"$PWD/.venv/bin/python" tests/fixtures/conformance/validate.py
PATH="$PWD/.venv/bin:$PATH" tests/ansible/run-local-contract.sh
PATH="$PWD/.venv/bin:$PATH" tests/ansible/run-multihost-record-handoff.sh
PATH="$PWD/.venv/bin:$PATH" tests/ansible/run-replay-contract.sh
PATH="$PWD/.venv/bin:$PATH" tests/callback/run-callback-contract.sh
PATH="$PWD/.venv/bin:$PATH" tests/callback/run-callback-failure-contract.sh
"$PWD/.venv/bin/molecule" test
PYTHONPATH=. "$PWD/.venv/bin/python" \
  tests/performance/test_budgets.py --json
PYTHONPATH=. "$PWD/.venv/bin/python" \
  tests/performance/test_persistence_budgets.py
```

Run the guarded live-Docker commands above on every matrix cell for which
Docker behavior is claimed, and run the structured negative lane only after
providing its explicit collection root. Before Gate-I exit, publish the
declared cells, skipped lanes, exact results, and any narrower support boundary
that follows from failures or unavailable environments.
