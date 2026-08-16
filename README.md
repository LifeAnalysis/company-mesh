# Company Mesh

Company Mesh is an installable, local-first MCP control plane for a company agent fleet.
Each machine runs one `companyd` daemon. Daemons connect through authenticated Iroh QUIC.
Local agents connect through a protected Unix socket and a bundled STDIO MCP adapter.

The current release is suitable for controlled teams and development data. It is not a
credential broker. Do not put credential values in messages, memory, logs, or task artifacts.

## System shape

```text
Codex / Codex CLI / Claude Code / Claude Desktop
                       |
                       | MCP over stdio
                       v
              company-mcp adapter
                       |
                       | owner-only Unix socket
                       v
                   companyd
                 /     |      \
        passkey gate   SQLite   signed Iroh messages
                               |
                            companyd
```

- The task graph returns only work with no open dependencies.
- Task completion needs deterministic tests and an independent review.
- Peer messages require enrollment, an active capability, an allowed scope, and a rate check.
- Remote messages enter a quarantine inbox. They cannot invoke MCP tools or a shell.
- Administrative actions need a fresh passkey assertion bound to the exact action.
- The optional reply loop is bounded and uses a direct executable. It never uses a shell.

## Install a signed release

Download the archive, checksum, and Sigstore bundle from one GitHub release. Then run:

```sh
scripts/install.sh \
  --archive company-mesh-VERSION-TARGET.tar.gz \
  --checksum company-mesh-VERSION-TARGET.tar.gz.sha256 \
  --bundle company-mesh-VERSION-TARGET.tar.gz.sigstore.json \
  --repository OWNER/REPOSITORY
```

The installer verifies the SHA-256 checksum and requires the Sigstore bundle. It also
checks the GitHub Actions identity. `--allow-unsigned` exists only for a trusted local
build. The installer puts files in `~/.local/share/company-mesh` and adds links in
`~/.local/bin`.

## Setup

Setup always asks for a permission profile. The default interactive choice is `observer`.
Setup also opens a local browser page at `http://localhost:39271` to create an
administrator passkey.

```sh
company-mesh setup \
  --organization acme \
  --node-name alice-mac \
  --agent-id agent:alice \
  --workload-id worker:alice \
  --spiffe-id spiffe://acme.example/company-mesh/alice \
  --spire-socket-path unix:///run/spire/sockets/agent.sock \
  --permissions collaborator \
  --session-minutes 30 \
  --notifications \
  --configure-all-clients \
  --mcp-adapter "$HOME/.local/share/company-mesh/company-mcp.mjs" \
  --install-service
```

Permission profiles:

| Profile | Agent permissions |
|---|---|
| `observer` | Read identity, ready tasks, memory, inbox, peers, and audit |
| `collaborator` | Observer access plus task work, review, memory proposals, and messages |
| `operator` | Collaborator access plus invites, blocking, unblocking, and revocation |

The adapter hides tools outside the selected profile. The daemon checks the same profile
again. Changing an existing setup requires the administrator passkey.

The workload fields reserve a stable identity binding for a future SPIRE Workload API
adapter. They are metadata today, appear in `company_identity`, and are not accepted as
authentication evidence. Omit all three flags when SPIRE is not being planned.

## Touch ID and timed sessions

The daemon starts with its agent mutation session locked. Unlock it before an agent can
create or claim tasks, submit work, record reviews, propose memory, or send peer messages:

```sh
company-mesh session unlock
```

The browser requests a platform authenticator with required user verification. On a Mac,
this normally uses Touch ID. The session expires after `--session-minutes`; the default is
30 minutes and the allowed range is 5 to 480 minutes. Read operations remain available.

Check or close the session:

```sh
company-mesh session status
company-mesh session lock
```

The daemon keeps the session only in memory. A daemon restart locks it. Invite creation,
joining, peer blocking, peer revocation, key rotation, and setup changes still require a
fresh action-bound passkey approval even during an unlocked session.

## Supported agent clients

`--configure-all-clients` configures:

- Codex and Codex CLI through the shared Codex MCP configuration.
- Claude Code at user scope through `claude mcp add`.
- Claude Desktop through `claude_desktop_config.json`. This covers the Desktop chat UI
  and local Code sessions.

Use individual flags when required:

```text
--configure-codex
--configure-claude-code
--configure-claude-desktop
```

Hosted Claude web cannot start a local STDIO process. It needs a future HTTPS MCP gateway.
The current adapter intentionally remains local.

## Start and manage the daemon

Setup can install a macOS LaunchAgent or Linux systemd user service. Manual operation is:

```sh
companyd --data-dir "$HOME/.local/share/company-mesh"
```

Service commands:

```sh
company-mesh service install
company-mesh service uninstall
company-mesh status
```

The service definition uses restart-on-failure. Linux also uses `NoNewPrivileges`, a
private temporary directory, a read-only home, and a narrow writable data path.

## Enroll a colleague

The inviter must have the `operator` profile. Invite creation requires a passkey touch.

```sh
company-mesh invite create \
  --invitee-label bob-laptop \
  --scope project:treasuryos \
  --rate-per-minute 30 \
  --expires-hours 24
```

Save the returned token in an owner-only file. Send that file through a separate trusted
channel. The colleague runs:

```sh
company-mesh join --token-file /private/path/company-mesh.invite
```

`company-mesh join --stdin` is also available. The positional token form can expose the
token in shell history and is not recommended.

Joining also requires their local administrator passkey. Invites are signed, expiring,
and single-use. Enrollment installs reciprocal capability IDs for the selected scopes.

Manage peers:

```sh
company-mesh peers list
company-mesh peers block ENDPOINT_ID
company-mesh peers unblock ENDPOINT_ID
company-mesh peers revoke ENDPOINT_ID
```

Block is reversible. Revoke requires a new enrollment. All changes need a passkey.

## Optional bounded reply loop

Enable it explicitly during setup with `--automatic-loop`. The maximum is ten messages
per invocation. Setup stores the lower configured limit.

```sh
company-mesh loop \
  --handler /absolute/path/to/reply-handler \
  --handler-arg value \
  --max-iterations 3
```

The handler receives one inbox message as JSON on standard input. It can return
`{"reply":"text"}`. Company Mesh starts the executable directly and applies a timeout and
an output limit. The reply still passes normal peer capability checks.

## Delegated project services

A colleague can expose a fixed local CLI operation without sharing its credential or
giving another agent shell access. For example, the owner creates an operations file:

```json
{
  "inspect": ["project", "inspect", "{project}"],
  "list-deployments": ["list", "{project}"]
}
```

The owner registers it. Registration requires a fresh Touch ID approval:

```sh
company-mesh delegation register-service \
  --name vercel \
  --executable /absolute/path/to/vercel \
  --operations-json /private/path/vercel-operations.json
```

The requesting agent uses `company_delegation_request`. The request appears in the
owner's verified inbox. The owner approves a strict subset:

```sh
company-mesh delegation approve \
  --request-id MESSAGE_ID \
  --operation inspect \
  --expires-minutes 30 \
  --max-calls 3
```

The requesting node stores the signed grant internally. The agent sees only its grant
ID and uses `company_service_call`. The grant token and Vercel credential never enter
model context. The daemon checks the peer, project, operation, expiry, call count,
registered executable digest, timeout, and output limit. It starts the executable
directly. It does not use a shell or accept arbitrary arguments.

Revoke an active grant at any time:

```sh
company-mesh delegation revoke --grant-id GRANT_ID
```

Command output is returned to the requesting agent. Register only operations whose
output is safe to share. Start with read-only commands. Do not register deployment,
secret, environment, domain, billing, or deletion operations for unattended use.

## Key rotation

Stop the daemon. Then run:

```sh
company-mesh key rotate --confirm
```

The command requires a passkey. It moves the old identity and SQLite files into a dated
archive. It creates a new endpoint identity and clean state. All peers must enroll again.

## Export the knowledge base

Export the persistent SQLite memory records to standard output or an owner-only JSON file:

```sh
company-mesh knowledge export
company-mesh knowledge export --output /private/path/company-knowledge.json
```

The `company-mesh-knowledge-export/v1` document includes memory records and provenance.
It excludes operational tables (including invitations, capability tokens, service grants,
nonces, peer addresses, and delivery receipts) and replaces common secret assignments and
Bearer values with `[REDACTED]`. This is defense in depth; credentials must never be put in
company memory in the first place.

## Optional operations adapters

The Rust library exposes local adapter boundaries without connecting to hosted services:

- `DurableDeliveryAdapter` consumes records from the SQLite `delivery_outbox`. Each record
  carries a portable subject and idempotency key; acknowledgements and retry attempts remain
  durable. This maps directly to a NATS JetStream publish with a message de-duplication ID.
- `AuditWitnessAdapter` receives a signed audit-chain checkpoint and returns a receipt that
  is stored in SQLite. The checkpoint and receipt fields cover the Rekor entry UUID, log
  index, integrated time, and inclusion proof needed by a future adapter.

Adapters must keep credentials outside messages, logs, and SQLite. See
[OPERATIONS_ADAPTERS.md](docs/OPERATIONS_ADAPTERS.md) for contracts and failure semantics.

## MCP tools

Read tools are available to all profiles:

- `company_identity`
- `company_tasks_ready`
- `company_memory_search`
- `company_peers`
- `company_inbox`
- `company_audit_tail`
- `company_audit_verify`

Collaborator and operator profiles also receive:

- `company_task_create`
- `company_task_claim`
- `company_task_submit`
- `company_review_record`
- `company_memory_propose`
- `company_peer_send`
- `company_delegation_request`
- `company_service_grants`
- `company_service_call`

No MCP tool can create invites, join networks, change permissions, block peers, revoke
peers, rotate keys, or access passkey material.

## Build and verify

```sh
npm ci
npm run typecheck
npm run build
npm run bundle
npm test
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Release packaging:

```sh
scripts/package-release.sh 0.1.0 aarch64-apple-darwin
```

GitHub tag builds create checksums, keyless Sigstore signatures, and build provenance.

## Current limits

- SQLite remains the canonical memory store. Graphiti is a planned temporal projection.
- Workload/SPIFFE fields are metadata only. Strong multi-workload authentication is not done.
- Reviews from two agent names in development mode are test-only. Production needs distinct
  authenticated workloads or separate enrolled nodes.
- Audit signatures detect modification and the witness boundary persists external receipts,
  but no Rekor adapter is bundled; deletion detection still requires an independent witness.
- There is no credential broker, malware scanner, file transfer layer, or remote HTTPS MCP.
- The bounded handler is an execution boundary. Review and sandbox every handler before use.

See [PLAN.md](PLAN.md), [WORKTREE_EXECUTION_PLAN.md](docs/WORKTREE_EXECUTION_PLAN.md),
[SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md), [THREAT_MODEL.md](docs/THREAT_MODEL.md),
and [PROTOCOL.md](docs/PROTOCOL.md).
