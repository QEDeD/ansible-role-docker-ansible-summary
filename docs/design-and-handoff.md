<!--
SPDX-FileCopyrightText: 2026 QEDeD

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Design review and handoff

## Product model

Docker Ansible Summary (DAS) answers one narrow question: what Docker state
was actually observed before and after a caller-defined run window?

```text
previous complete post A -> current pre B -> run window -> current post C
                         A -> B                 B -> C
```

`A -> B` describes a difference between observation endpoints. `B -> C`
describes a difference across the caller's window. Neither delta attributes a
cause to Ansible, a person, a Git revision, or any other actor.

DAS deliberately owns Docker discovery, canonical normalization, endpoint
comparison, the bounded A/B/C lifecycle store, a stable machine result, and a
deterministic human report. It does not own controller command or Git logging,
consumer orchestration, deployment placement, monitoring, remediation,
unbounded history, or support for non-Docker runtimes.

A separate run recorder may receive the same opaque caller-supplied
correlation ID. The two tools complement one another, but neither discovers,
invokes, parses, stores for, or depends on the other.

## Responsibility graph

The implementation follows one canonical path:

```text
public inputs
  -> controller validation and disabled short circuit
  -> one managed-node module call
  -> bounded Docker CLI catalogue and selected inspect chunks
  -> canonical observation
  -> lifecycle transition and comparison
  -> atomic bounded per-instance store
  -> allowlisted machine result
  -> pure ReportModel and deterministic renderer
  -> one controller display call
```

The controller action plugin owns variable-namespace validation, result
sanitization, failure policy, report construction, and callback display. The
managed-node module owns discovery and persistence orchestration. Pure
functions own normalization, comparison, transition, image projection,
ReportModel construction, and rendering. The POSIX store owns descriptor-
relative namespace validation, locking, replay/conflict handling, retention,
and atomic replacement.

There is no object-proportional Ansible task graph and no presentation-only
Docker query. An enabled phase has one role-owned task and at most one remote
module invocation. A disabled phase returns on the controller before remote,
Docker, or filesystem work.

## Lifecycle and truth boundaries

- `pre` observes B and opens a run record. It never advances the baseline.
- `post` with the matching record observes C, derives B -> C, closes the
  record, and advances the baseline only when C is complete.
- post-only `post` records C without inventing B -> C.
- `status` observes current state without opening or reading the store.
- check mode observes and simulates the requested operation without opening or
  reading the store.
- an identical retained replay returns the committed result without
  rediscovery or another store write.
- optimistic revision mismatch is a hard conflict, not an inferred merge.

Complete, partial, unavailable, and complete-empty observations remain
distinct. Only compatible complete endpoints can assert authoritative
additions or removals. Full image reference and image ID participate in
canonical equality; friendly image/version labels are display projections and
never decide persisted truth.

## Simplicity and maintainability decisions

The role intentionally has 13 public variables and only 8 defaults. Optional
operation-specific values remain omitted so the disabled path is safe and
strict validation can distinguish omission from null. There are no
`_default`/`_auto`/`_custom` extension layers because the v1 use case has no
composable list that needs them.

The single task boundary is implemented with an action plugin plus one module
rather than a large YAML/Jinja task graph. This adds Python code, but it keeps
Docker process work, raw results, callback noise, failure projection, and
state transactions bounded and independently testable. Python modules are
split by responsibility rather than by legacy data shape.

The v1 renderer is ASCII and fixed-width by input. It favors deterministic,
collision-safe projection over terminal probing or semantic version guesses.
Tags are opaque: DAS does not invent `latest`, strip `v`, or claim
upgrade/downgrade direction.

The state store retains only comparison and replay evidence. It is not a
general audit log or history browser. Count and byte ceilings, a fixed lock
timeout, stable lock inode, strict ownership/mode checks, and same-directory
atomic replacement are part of the safety contract rather than public tuning
surfaces.

## External-role convention review

The planning review compared locally pinned MASH ecosystem roles:

| Reference | Immutable revision | Relevant evidence |
|---|---|---|
| `ansible-role-qbittorrent` `v5.2.1-1` | `6dc64b49f66aa82ce0d15613fc6d44cbd7e316bd` | Role-root layout, namespaced variables, task naming, metadata, lint and release shape |
| `ansible-role-nextcloud` `v34.0.2-0` | `7496423263b10eec3ac3eabfd0f1d68ff5f5dc71` | SPDX/REUSE practice, documentation, immutable consumer pinning, and Molecule plumbing |

Adopted conventions are a conventional role-root layout, a stable namespaced
public surface, FQCN task actions, descriptive task names, SPDX/REUSE,
dependency pins, focused lint lanes, and proportionate Molecule coverage.

Adapted conventions are the test topology and action/module boundary. A
daemonless local Molecule scenario proves the Ansible role surface, while pure
logic, fake-Docker adapter, persistence, callback, performance, and opt-in
live-Docker behavior remain separate proof lanes.

Rejected conventions are service installation/uninstallation branches,
forced privilege escalation, runtime role dependencies, floating test images,
privileged/systemd test containers, broad platform claims, generic
idempotence as a substitute for replay tests, and extension variables without
a demonstrated DAS use case.

These repositories are convention evidence, not behavioral authority for an
observational diagnostic role.

## Old/new semantic parity

| Operator use case | Old DAS | Standalone v1 | Classification |
|---|---|---|---|
| Immediate overview | Late MDAD table of changed and unchanged services | One host-identifiable post/status table with changed and unchanged rows | Preserved semantic intent |
| Confirm no change | Explicit no-change summary | Exact unchanged B -> C without causal inference | Preserved semantic intent |
| First observation | Empty baseline was also the signal for first run, so uninitialized and known-empty could blur | Explicit first/pre/post-only lifecycle and authoritative complete-empty observation | Defect fixed |
| Detect drift | One display-oriented baseline comparison | Separate A -> B and B -> C endpoint deltas | Intentionally changed |
| Trust image identity | Friendly parsed strings could influence equality and invent defaults | Full reference and image ID decide truth; friendly text is presentation only | Defect fixed |
| Same-tag replacement | Equal simplified tag could hide a new immutable image | Equal configured reference plus changed image ID is an exact material change | Defect fixed |
| Runtime transition/recreation | Friendly-version equality could hide stop/start/restart or container replacement | Runtime state, restart evidence, and container identity have explicit canonical change kinds | Defect fixed |
| Include stopped containers | Live path could omit them and misclassify them as removed | Catalogue includes running and stopped containers | Defect fixed |
| Additions/removals | Discovery and scope behavior could hide cases; all-removals could print only an empty message | Compatible complete endpoints preserve additions, removals, and a table containing every all-removal row | Preserved semantic intent; defect fixed |
| Partial/unavailable evidence | Failure, empty, skipped, and missing data could blur | Partial and unavailable reports name evidence gaps and never claim authoritative absence | Defect fixed |
| Multiple hosts | Callback output existed per Ansible host but had no frozen contamination/interleaving proof | Each block names its host; two-host/four-fork captures prove unique contiguous data under the supported callback lane | Preserved semantic intent; contract strengthened |
| Retain run context | Multiple fact/history projections could diverge | One atomic bounded baseline and replayable journal | Intentionally changed |
| Browse long history | History-oriented legacy entry points | No interactive or unbounded history subsystem | Deferred |
| Quiet/fast execution | Large object-sensitive task graph and callback surface | One role task/module call per enabled phase and bounded Docker processes | Defect fixed |
| Exact legacy table bytes | Formatting changed repeatedly | Versioned deterministic renderer with new geometry | Irrelevant accidental behavior |
| Reuse outside MDAD | Embedded MDAD role | Consumer-neutral external Docker role | Preserved semantic intent |

The old role remains a user-experience sanity check, not a byte-compatibility
or implementation template. A quantitative speed/noise comparison remains
unknown until both implementations can be measured with matched fixtures and
callback conditions.

### Representative case evidence

| Case | Old operator experience and evidence | New captured/executable evidence | Truthfulness change | Noise/performance status | Parity conclusion |
|---|---|---|---|---|---|
| No change | Existing snapshots show an explicit unchanged row/footer | Scenario 3 plus `RendererGoldenTests.test_exact_fixture_blocks` renders unchanged rows | Separates B -> C no-change from any A -> B drift and makes no causal claim | New role boundary is measured; matched old/new runtime is `UNKNOWN` | Preserved intent with stronger endpoint semantics |
| Material image change | Simplified friendly labels produced an updated row | Scenarios 5–6 and focused comparison/report tests render exact image/reference facets | Full configured reference and immutable image ID decide equality | Pure pipeline measured; matched legacy timing is `UNKNOWN` | Preserved visibility; defective equality fixed |
| Same tag, new image | Could remain `UNCHANGED` when the simplified tag matched | Guarded live test `test_same_tag_with_new_offline_image_id` plus image-projection tests | Detects changed immutable content without inventing version direction | Two Docker processes at the tested size; no matched legacy run | Defect fixed |
| Stopped container | Live discovery could omit it and make it appear removed | Guarded lifecycle test observes simultaneous running/stopped rows and stop/start transitions | Distinguishes stopped from absent | Bounded catalogue plus inspect chunks; legacy timing `UNKNOWN` | Defect fixed |
| Addition | Existing table could show `CHANGED (ADDED)` | Scenario 11, focused change-kind binding, and guarded lifecycle test | Requires compatible complete endpoints before asserting addition | No per-object Ansible event in v1; unmatched old event count | Preserved intent with stronger evidence rule |
| Removal | Existing table could show `CHANGED (REMOVED)`, but stopped/partial evidence could create false removals | Scenario 12 and guarded lifecycle test | Only complete compatible evidence asserts absence | Same bounded process shape; matched runtime `UNKNOWN` | Preserved intent; false-positive paths fixed |
| All removals | State/history could record removals while console printed only the empty-scope message | Scenario 13 and `test_zero_current_table_distinguishes_empty_from_all_removals` render every removed row | Authoritative empty C is distinct from unavailable C | Exact output bytes are golden-tested; legacy timing `UNKNOWN` | Defect fixed while preserving removal intent |
| Partial | Missing required evidence could blur with empty or failure | Scenarios 15–16 and exact partial ReportModel/table/warning tests | Known rows remain visible; absence is explicitly non-authoritative | One compact two-line warning where a final table would mislead | Defect fixed |
| Unavailable | Primary discovery normally hard-failed with SDK/daemon details | Scenarios 17–18, fake-process classifiers, and expected-failure callback capture | Uses a bounded reason/warning and never invents an empty catalogue | One compact warning or bounded failure envelope; no raw result dump | Intentionally changed to safer diagnostics |
| First run/empty | Empty baseline doubled as uninitialized state | Scenario 1, complete-empty discovery test, and explicit lifecycle records | Known-empty, no baseline, post-only, and unavailable are distinct | One catalogue process for complete empty; old matched timing `UNKNOWN` | Defect fixed |
| Multiple hosts | Ansible naturally produced host results, but atomicity and contamination were not a frozen contract | Two-host/four-fork callback capture proves one unique contiguous block per host; multihost pre/post harness proves distinct record IDs and state | Host-local A/B/C and record identity are explicit; no cross-host atomicity implied | Callback capture classifies one role task plus one harness task; pre/post harness measures two role tasks and eight fake-Docker processes total | Preserved intent; transport and isolation contract strengthened |

The new evidence comes from actual production functions, exact renderer
goldens, direct Ansible captures, and the guarded disposable daemon. The
old-side evidence comes from reviewed source, existing snapshots/tests, and
focused history; old DAS was not rerun against matched fixtures. Static
structure shows 65 old task definitions, 14 loop tasks, and object-sensitive
work, while new captures prove one role-owned task per enabled phase and zero
per-object Ansible events. Those are different evidence units, so they justify
the architectural statement “structurally quieter,” not a numeric old/new
event or wall-time speedup. Every comparative latency claim remains
`UNKNOWN`.

## Contract provenance and handoff state

The normative v1 planning source remains the frozen package in the MDAD
planning worktree at commit
`32c7c106fe1b7f6a126f094774cb5531f44fb0e4`. The copied conformance corpus in
this repository records that provenance. This repository owns implementation
and test evidence; it does not silently replace or fork the normative source.

Initial ownership is contributor-owned by QEDeD. The intended future
`mother-of-all-self-hosting/ansible-role-docker-ansible-summary` repository is
a separate governance destination. Contributor-branch publication preserves
the current ownership model; no release, ownership transfer, consumer
integration, or deployment follows from publication alone.

The exact local evidence and remaining Gate-I work are tracked in
[`validation-status.md`](validation-status.md).
