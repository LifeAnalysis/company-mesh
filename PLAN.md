# Company Mesh implementation plan

## Objective

Build a local-first company agent mesh. Each machine runs one authenticated Iroh daemon. Local Codex and Claude sessions use a small MCP server that connects to the daemon through a protected Unix socket.

The fleet graph schedules work. Each node runs a bounded loop. The memory layer keeps signed, scoped, temporal records with provenance.

## Security invariants

1. MCP is a local capability boundary. It is not the remote transport.
2. An Iroh endpoint ID authenticates a node. It does not grant authority.
3. Remote messages are signed, expire, and contain replay-resistant nonces.
4. Remote peers cannot invoke local shell or MCP tools.
5. Secrets never enter model context or company memory.
6. Task completion requires deterministic evidence and an independent reviewer.
7. Memory writes retain source provenance and status.
8. The event log is append-only.
9. Tool failures are typed failures.
10. The daemon fails closed for invalid messages and state transitions.
11. Administrator actions require a fresh action-bound passkey assertion.
12. The passkey private key never enters model context or daemon storage.
13. Mutating agent work requires a short in-memory session opened by verified WebAuthn.

## Implementation status

Complete in this repository:

- Phases 0 through 4 for peer messages and local MCP actions.
- Signed, single-use invitations and reciprocal peer capabilities.
- Peer blocking, unblocking, revocation, rate limits, and key rotation archives.
- WebAuthn administrator gates for trust changes.
- Permission-profile setup and tool filtering.
- macOS and Linux user services.
- Codex, Codex CLI, Claude Code, and Claude Desktop configuration.
- Optional notifications and a bounded executable reply loop.
- Signed GitHub release packaging with checksums and provenance.

Still planned:

- Production graph execution with isolated worktrees.
- Graphiti projection and full memory lifecycle controls.
- Remote audit witnesses, workload identity, secret brokering, and incident drills.

Local foundations now present for the remaining work:

- SPIFFE/SPIRE-ready workload identity metadata, without treating configuration as proof.
- SQLite outbox and typed durable-delivery adapter boundary suitable for NATS JetStream.
- Signed chain checkpoints and durable witness receipts suitable for a Rekor adapter.
- Redacted JSON export of the canonical SQLite memory knowledge base.

## Delivery order

1. Implement durable identity, event storage, task state, and memory records.
2. Implement the Iroh request and acknowledgement protocol.
3. Implement a protected local RPC socket.
4. Implement a small MCP adapter over that socket.
5. Test task dependencies, review gates, memory provenance, signature validation, replay protection, and two-node messaging.
6. Test the MCP adapter with a real MCP client.
7. Add Graphiti as an optional projection after the canonical event and scope model is stable.

## Detailed delivery plan

### Phase 0: invariants and protocol

- Freeze the envelope schema and versioned Iroh ALPN.
- Define scopes for task, project, team, and company data.
- Define typed failures and strict message size, expiry, and replay rules.
- Keep remote transport separate from local MCP tool execution.

Exit gate: malformed, expired, replayed, or mismatched signatures fail closed.

### Phase 1: one trustworthy local node

- Keep durable endpoint identity in an owner-only data directory.
- Store tasks as an explicit dependency graph.
- Require a bounded host loop and typed tool errors.
- Require deterministic test evidence and an independently stored review.
- Store scoped memory with source provenance and temporal fields.
- Sign each append-only audit event and chain it to the prior event.

Exit gate: unit tests prove graph readiness, provenance, self-review rejection, and
audit-chain validation.

### Phase 2: authenticated peer transport

- Connect nodes with Iroh authenticated QUIC.
- Sign application envelopes with the endpoint key.
- Store nonces durably and reject replay.
- Put verified peer messages in a quarantine inbox only.
- Add strict timeouts, quotas, and resource limits.

Exit gate: two real daemons exchange one message and reject the replay.

### Phase 3: local MCP boundary

- Run one small STDIO MCP adapter per agent host.
- Send requests to `companyd` through a mode-0600 Unix socket.
- Expose narrow tools. Do not expose policy, trust, credentials, or raw SQL.
- Return typed MCP failures.

Exit gate: an official MCP client lists and calls all intended tools.

### Phase 4: peer enrollment and capabilities

- Add an administrator-signed node registry.
- Add revocable capability grants with action, scope, quota, and expiry.
- Require approval for trust changes and high-risk outbound actions.
- Bind local agent identity to an operating-system or workload identity.

Exit gate: unknown nodes and out-of-scope actions are denied by default.

### Phase 5: graph execution

- Compile work specifications into explicit DAGs.
- Give each ready task a clean Git worktree and narrow role.
- Limit fan-out and total cost.
- Merge only after lint, type, test, and independent review gates pass.
- Persist checkpoints so a stopped loop can resume without duplicate side effects.

Exit gate: a multi-task fixture runs safe parallel waves and never merges a failed node.

The complete state machine, worktree rules, reviewer boundary, merge queue, cleanup
rules, and acceptance matrix are in [docs/WORKTREE_EXECUTION_PLAN.md](docs/WORKTREE_EXECUTION_PLAN.md).

### Phase 6: company memory

- Keep signed events as the source of truth.
- Project approved events into Graphiti for temporal graph retrieval.
- Filter every retrieval by tenant, team, project, sensitivity, and purpose.
- Treat retrieved text as quoted data, never as system instructions.
- Add correction, supersession, retention, and deletion workflows.

Exit gate: authorization tests prevent cross-scope retrieval and temporal tests return
the correct fact for a requested point in time.

### Phase 7: proof and operations

- Record traces for tool calls, policy decisions, and state changes.
- Replay clean test traces in isolated environments.
- Add remote audit witnesses, metrics, rate limits, key rotation, and peer revocation.
- Add a global pause switch and a quarantine workflow.

Exit gate: attack, failure, recovery, and revocation drills pass before unattended use.

## Source principles

- Bernstein: deterministic DAG scheduling and conservative parallel declarations.
- agent-worktree: isolated worktrees and merge preflight.
- Beads: durable dependency state and ready-work queries.
- Waku: a legible bounded agent loop, with typed error handling added here.
- Serena: narrow, symbol-level context.
- insane-research: deterministic promotion from candidate output to verified output.
- claude-review-loop: independent review, changed here to fail closed for unattended work.
- Workshop: trace replay and evidence-based evaluation.
- Graphiti: temporal graph projection. It is not the authorization layer or source of truth.

Source repositories:

- <https://github.com/sipyourdrink-ltd/bernstein>
- <https://github.com/nekocode/agent-worktree>
- <https://github.com/wshobson/agents>
- <https://github.com/fivetaku/insane-research>
- <https://github.com/gastownhall/beads>
- <https://github.com/ShenSeanChen/waku-agent>
- <https://github.com/oraios/serena>
- <https://github.com/obra/superpowers>
- <https://github.com/hamelsmu/claude-review-loop>
- <https://github.com/raindrop-ai/workshop>
- <https://github.com/getzep/graphiti>

## MVP acceptance criteria

- Two local daemons exchange an authenticated Iroh message.
- A replayed envelope is rejected.
- A task with open dependencies is not ready.
- A task cannot complete without passing tests and an independent reviewer.
- A memory proposal without source provenance is rejected.
- MCP lists the intended tools and can call identity, task, memory, inbox, and peer tools.
- No MCP tool can change peer trust, policy, or credentials.
