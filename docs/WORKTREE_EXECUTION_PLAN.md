# Worktree execution plan

## Goal

Add a production execution layer above `companyd`. The scheduler controls the graph.
Each graph node runs a bounded agent loop in a separate Git worktree. No agent can
merge its own output or approve its own work.

## Fixed safety rules

1. The scheduler is deterministic code. It is not a model prompt.
2. A task starts only when all dependencies have an accepted result.
3. Each task gets one branch and one worktree.
4. The task receives a narrow role, path scope, tool scope, time limit, iteration
   limit, and cost limit.
5. Credentials do not enter a worktree, prompt, log, patch, or review artifact.
6. A worker cannot approve, merge, or change its own permissions.
7. Tests and policy checks run as direct processes. Agents cannot declare them green.
8. Merge is serial, even when execution is parallel.
9. Every transition is idempotent and recorded in the signed event log.
10. Cleanup starts only after artifacts and evidence are durable.

## Components

### 1. Specification compiler

Input is a versioned work specification. It contains tasks, dependencies, declared
paths, role, acceptance commands, reviewer policy, and resource limits. The compiler:

- validates task identifiers and path scopes;
- rejects cycles;
- rejects overlapping write scopes in one parallel wave;
- expands defaults into an immutable run manifest;
- hashes the manifest and records `run.planned`.

The compiler does not infer hidden dependencies. A planner agent can propose a graph,
but deterministic code must validate and freeze it.

### 2. Scheduler

The scheduler queries tasks with no open blockers. It selects a bounded ready wave.
Initial limits are four workers per repository and two workers per shared subsystem.
The scheduler uses leases with an expiry and heartbeat. A restarted scheduler can
recover an expired lease without starting a second active worker.

State machine:

```text
planned -> ready -> leased -> running -> candidate -> reviewing -> merge_ready
                                  |          |            |            |
                                  v          v            v            v
                                failed     failed       changes      merged
                                                           |
                                                           v
                                                        running
```

Terminal states are `merged`, `failed`, `cancelled`, and `quarantined`.

### 3. Worktree allocator

For run `R` and task `T`, use branch `mesh/R/T` and a path below a dedicated worktree
root outside the source checkout. Creation uses explicit arguments:

```text
git worktree add -b mesh/R/T WORKTREE_PATH BASE_COMMIT
```

Before creation, the allocator verifies that:

- the base commit equals the frozen run manifest;
- the branch and path do not exist;
- the target is below the configured worktree root;
- the repository has no unresolved Git operation;
- no untracked credential file will be copied.

The allocator records the branch, base commit, worktree path, and Git common directory.
It never uses a shell, glob, or model-supplied command string.

### 4. Worker loop

The worker starts the selected agent client as a direct child process. Its MCP profile
is generated from the task manifest. The worker gets task and memory read access plus
write access only for its task scope. It does not get peer administration tools.

The loop ends on the first of these conditions:

- the model stops requesting tools;
- the iteration limit is reached;
- the wall-time or cost limit is reached;
- the worker loses its lease;
- a global pause or task cancellation is received.

Tool failures remain typed failures. A failure string cannot count as successful
evidence. Each loop checkpoint stores the input event cursor, output commit, tool trace
digest, and resource counters.

### 5. Verification gate

The host runs the manifest commands in the worktree with a clean environment. The
first version supports exact command arrays only. It does not support shell text.

The gate records:

- command and executable digest;
- exit code;
- bounded stdout and stderr digests;
- test report path and digest;
- candidate commit and tree hash;
- changed paths compared with the base commit.

The gate fails if a changed path is outside the declared write scope. Security-sensitive
paths can require an extra policy check or can be denied for unattended work.

### 6. Independent review

A different authenticated workload receives the frozen specification, candidate diff,
and verification evidence. It cannot edit the candidate worktree. It signs one of:
`approve`, `changes_requested`, or `reject`.

Independence means a different workload identity and reviewer capability. A different
prompt on the same node is not sufficient. High-risk paths can require two reviewers,
including one human passkey approval.

### 7. Merge queue

One merge worker owns a repository lock. For each approved candidate it:

1. fetches the current target ref;
2. verifies that approval matches the candidate commit;
3. performs a merge-tree or no-commit preflight;
4. rebases or returns the task to `changes_requested` if the base is stale;
5. merges with an auditable merge commit;
6. runs the post-merge acceptance commands;
7. records `task.merged` with the resulting commit.

If post-merge checks fail, the queue stops. It creates a quarantine event. It does not
silently reset shared history. A human or an approved recovery task must make a revert.

### 8. Cleanup

Cleanup requires a terminal state and durable artifacts. It first runs `git worktree
remove` for the exact recorded path. It deletes a task branch only after merge, explicit
abandonment, or archive. Failed work remains available for the configured retention
period. A periodic reconciler reports orphaned worktrees before it removes them.

## Durable records

Add these tables or equivalent versioned records:

- `runs`: manifest hash, base commit, target ref, status, limits, timestamps;
- `run_tasks`: dependency state, role, scopes, lease, attempts, candidate commit;
- `worktrees`: canonical path, branch, base commit, owner, cleanup state;
- `executions`: client, model, loop limits, trace digest, result;
- `gate_results`: command evidence and candidate tree hash;
- `review_decisions`: reviewer workload, candidate commit, verdict, signature;
- `merge_records`: preflight base, merge commit, post-merge evidence;
- `artifacts`: content digest, media type, size, retention, storage location.

Every mutation also writes a signed audit event. Database changes and audit writes must
use one transaction.

## Credentials and process isolation

- Start with a minimal environment allowlist.
- Use short-lived brokered credentials. Do not copy `.env`, SSH keys, cloud profiles,
  browser sessions, or the Iroh secret key into a worktree.
- Redact process output before it reaches logs or models.
- Deny network access by default where the host platform supports it.
- Give each worker a separate temporary directory and cache namespace.
- Use an operating-system sandbox or container for unattended execution. A Git
  worktree isolates files and branches. It is not a security sandbox.

## Recovery and idempotency

All commands use a run ID, task ID, attempt number, and idempotency key. After restart,
the scheduler compares durable state with Git state and live process leases. It never
assumes that a process failure means that a Git operation did not finish.

Recovery tests must cover a crash during worktree creation, candidate commit, review,
merge preflight, merge commit, post-merge test, and cleanup.

## Delivery sequence

1. Add run, task, lease, worktree, and evidence records.
2. Build the specification compiler and cycle/path-conflict tests.
3. Build the bounded scheduler with a fake worker.
4. Build the safe worktree allocator and orphan reconciler.
5. Add one real client runner with a narrow MCP profile.
6. Add deterministic gates and path-scope checks.
7. Add independent reviewer identity and signed decisions.
8. Add the serial merge queue and post-merge quarantine.
9. Add cleanup, retention, pause, cancellation, and crash recovery.
10. Add end-to-end fixtures for parallel waves and conflicting changes.

## Acceptance tests

- A cycle never starts.
- A blocked task never gets a lease.
- Parallel tasks cannot have overlapping declared write paths.
- Two workers never share a worktree or branch.
- A worker cannot write outside its declared paths.
- A failed or timed-out gate cannot enter review.
- A worker cannot review its own candidate.
- Approval for commit A cannot approve commit B.
- Only one merge runs at a time.
- A stale candidate returns to work instead of forcing a merge.
- A failed post-merge check pauses the queue.
- A scheduler restart does not duplicate side effects.
- Cleanup never removes active or unarchived failed work.
- No fixture secret appears in prompts, logs, diffs, artifacts, or memory.

The phase is complete only when a multi-task fixture runs two safe parallel waves,
rejects one failed node, merges the valid nodes in order, survives an injected crash,
and leaves no active worktrees.
