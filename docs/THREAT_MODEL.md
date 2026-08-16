# Threat model

## Protected assets

- Node identity keys
- Company memory and its provenance
- Task and review state
- Agent messages
- Audit history
- External service credentials, when a separate broker is added

## Trust boundaries

1. The local MCP adapter is less trusted than `companyd`.
2. Every remote Iroh peer is untrusted until enrollment and authorization succeed.
3. Model output is untrusted input to policy checks.
4. Memory retrieval is data. It is not an instruction channel.
5. A review is independent only when its authenticated actor differs from the worker.
6. Local administrator actions are separate from agent MCP actions.
7. A passkey proves human presence for one action. It does not make model output safe.

## Controls in this MVP

- A persistent Ed25519 key identifies each Iroh endpoint.
- Envelopes have signatures, payload hashes, expiry times, and nonces.
- The receiver checks that the envelope signer matches the Iroh peer identity.
- Replay nonces are durable in SQLite.
- Remote messages enter an inbox only. They cannot invoke tools.
- The Unix socket and data directory use owner-only permissions.
- The daemon refuses to replace a non-socket path.
- Request and envelope sizes are bounded.
- Task dependencies and state transitions are checked in code.
- Task completion needs passing tests and an approved independent review record.
- Memory requires a scope and source provenance.
- Audit events form a signed BLAKE3 hash chain.
- Signed invites expire and can be used only once.
- Enrolled peers have narrow message kinds, scope prefixes, capability IDs, and rates.
- Unknown, blocked, revoked, and out-of-scope peers fail closed.
- Local MCP tools are filtered by the setup permission profile.
- Invite, join, block, unblock, and revoke RPCs require a fresh WebAuthn assertion.
- Mutating agent RPCs require an in-memory, time-limited session opened with verified
  platform WebAuthn. Daemon restart and explicit lock remove the session.
- Passkey challenges are action-bound, memory-resident, short-lived, and single-use.
- The passkey private key stays in the platform authenticator. Agents never receive it.
- Key rotation archives the old identity and state, then requires re-enrollment.
- The optional agent loop has an iteration limit, timeout, output limit, and no shell.

## Controls required before production

1. Bind local agent identity to an operating-system identity or workload certificate.
2. Put secret access behind a separate broker. Return handles, not secret values.
3. Add outbound data-loss checks for sensitive text and attachments.
4. Add total storage quotas and longer-window peer circuit breakers.
5. Replicate signed audit checkpoints to independent witnesses.
6. Encrypt sensitive database fields and define retention and deletion rules.
7. Run every worker in an isolated worktree and process sandbox.
8. Require separate workload credentials for independent reviews.
9. Add trace replay and policy regression tests before unattended operation.
10. Add a global pause switch and remote incident coordination.
11. Add phishing-resistant recovery with two administrator passkeys.
12. Add an HTTPS MCP gateway only after tenant isolation and remote authentication exist.

## Friend-agent compromise case

A compromised friend node can send valid messages only while it remains enrolled and
active. Its capability limits the message kind, scope, and per-minute rate. It cannot
call a local MCP tool, run a shell command, complete a task, read memory through Iroh,
or perform administrator actions. Blocking takes effect immediately. Revocation requires
new enrollment.

A compromised local agent can request an administrator challenge, but it cannot complete
the WebAuthn assertion without the administrator passkey and user verification. It also
cannot reuse an assertion for a different action or a second request.

The remaining local risk is the operating-system user boundary. Malware running as the
same user can read local data and interfere with processes. Use host security, sandboxing,
disk encryption, and separate workload identities for high-value deployments.
