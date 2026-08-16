# Security audit

Audit date: 2026-08-16.

This is an engineering audit. It is not a formal penetration test or an external
cryptographic review.

## Scope and checks

- Rust source, unsafe patterns, local socket handling, Iroh message handling, passkey
  approval, enrollment, capabilities, service files, installer, and release workflow.
- `cargo clippy --workspace --all-targets -- -D warnings`.
- `cargo test --workspace`: 30 tests, including platform sandbox execution, symlink-safe
  owner-file writes, exact passkey parameter binding, typed delegated parameters, replay
  rejection, capability enforcement, durable adapters, knowledge redaction, and two-node
  Iroh exchange.
- `cargo audit`: no known vulnerable Rust crates. Two allowed maintenance warnings remain.
  `paste 1.0.15` is present on non-macOS Iroh dependency paths. `proc-macro-error2
  2.0.1` is a build-time dependency of `biscuit-auth` through `biscuit-quote`.
- `npm audit`: zero known vulnerabilities across production and development packages.
- Gitleaks source scan: no detected secret.
- Shell syntax checks for release and install scripts.
- Live MCP, observer-permission, two-node, Codex CLI, Claude Code, and Claude Desktop
  configuration tests.

## Fixed findings

### Critical: development authentication bypass in release builds

Hidden `--dev-mode` and `--dev-no-passkey` flags disabled the administrator gate. Both
flags now fail before state access in release builds. They remain available only in
debug builds for local automated tests.

### High: missing passkey could create a new administrator

Setup could register a new passkey when an existing node had identity or state files
but no passkey file. Setup now fails closed. Recovery needs an explicit future recovery
procedure.

### High: unsigned installation was the default

The installer now requires a Sigstore bundle. A user must explicitly select
`--allow-unsigned` for a trusted local build. Archive entries are checked for absolute
or parent-traversal paths before extraction.

### High: unbounded connection tasks and network waits

Remote Iroh work is limited to 64 concurrent connections. Local RPC work is limited to
32 clients. Connection, stream, read, write, and acknowledgement operations now have
timeouts. Message sizes were already bounded.

### High: long-lived and over-broad agent mutation authority

Routine task, review, and memory mutations now use a separate in-memory session from
external messages, delegation requests, and service calls. Opening either session
requires platform WebAuthn with user verification. The defaults are 120 minutes for
routine work and 15 minutes for external effects. The daemon starts locked, restart locks
it, and the operator can lock both immediately. High-risk administration requires a
fresh assertion bound to the complete parameter digest. The browser shows a safe action
summary and never displays an invitation bearer value.

### Medium: mutable GitHub Actions

All release and CI actions are pinned to full commit identifiers. Dependabot watches
Cargo, npm, and GitHub Actions updates.

### Medium: invite tokens in shell history

`company-mesh join` now accepts `--token-file` and `--stdin`. The positional form stays
available for compatibility, but setup guidance must use a file or standard input.

### Low: build files confused secret scanning

The Gitleaks configuration excludes generated dependency and build directories. The
source-only scan is clean.

## Open risks

### Operating-system user compromise

The Unix socket, configuration, database, passkey public credential, and Iroh identity
are protected from other users by file permissions. Malware running as the same user
can read or modify them. A passkey protects high-risk trust changes, but it cannot make
a fully compromised host trustworthy. Use full-disk encryption, operating-system
updates, endpoint detection, and a separate service account for unattended nodes.

### Bearer invitation theft

An invitation is signed, expires, and is single-use, but it is still a bearer secret.
Send it through an authenticated private channel. A future format must optionally bind
it to the expected invitee endpoint before it is suitable for unattended enrollment.
The database also stores the active token. A future migration should store only its
digest.

### One administrator passkey

The current node stores one public passkey credential. Loss of that authenticator can
make administration unavailable. Add two-passkey enrollment, a printed offline
recovery code, and an explicit recovery ceremony before production deployment.

### Audit transaction and external witness

The event chain detects later database edits, but all state mutations and audit appends
do not yet share one SQLite transaction. A crash can leave state without its matching
event. Move each mutation and its audit append into one transaction. Anchor periodic
chain heads to a separate witness before using the log for compliance evidence.

### Agent execution sandbox

Remote peers can only place data in the inbox. They cannot invoke local tools or shell.
The optional local reply loop can start a configured executable. It is bounded, but it
is not an operating-system sandbox. Do not enable it for untrusted content until the
worktree executor uses containers or platform sandboxing, an environment allowlist,
network controls, and brokered short-lived credentials.

Delegated services are narrower than the reply loop. The owner registers an absolute
executable and fixed arguments with Touch ID. Grants bind the peer, project, operations,
expiry, and call count. The executable digest, timeout, and output size are checked.
The child runs in `sandbox-exec` on macOS or Bubblewrap on Linux. The daemon clears its
environment, uses an owner-only temporary working directory, denies network by default,
and exposes only registered read-only paths. A service can opt in to broad outbound
network access. Domain-level egress control is not implemented; use a separate proxy for
that boundary. A credential-provider contract and short-lived file lease exist, but no
Keychain, Vault, or OpenBao provider is bundled. Output can contain sensitive data.
Register read-only commands and review their output behavior before granting them.

### Prompt injection and company memory

Signed text can still be malicious text. Treat remote messages and retrieved memory as
quoted data. Never insert them into system instructions. Memory authorization,
correction, retention, and deletion controls remain planned.

### Hosted Claude web access

Claude Desktop and Claude Code can start the local STDIO adapter. A hosted browser
session cannot reach a local Unix socket. Supporting that case needs a separate public
HTTPS MCP gateway, OAuth, tenant isolation, and a new external review.

## Iroh, Tailscale, and other security projects

Iroh already provides encrypted QUIC connections and cryptographic endpoint identities.
Company Mesh adds signed application envelopes, capabilities, scopes, quotas, passkey
administration, and replay protection. Tailscale is not required to encrypt Iroh again.

An overlay network can still help with device enrollment and organization-wide network
policy:

- Tailscale or Headscale: useful for managed device membership and ACLs. Use it as an
  optional host boundary, not as a replacement for application capabilities.
- NetBird: an open-source WireGuard control plane with similar device and network policy
  goals.
- Nebula: a smaller certificate-based overlay for teams that want self-hosted network
  membership.
- SPIRE: a strong future choice for short-lived workload identity. It addresses the
  identity of each daemon or worker, not P2P transport.
- Teleport: useful for human administrator access and audit. It is heavier than this
  daemon needs for peer messaging.

Recommended production shape:

1. Keep Iroh for authenticated peer transport.
2. Keep Company Mesh capabilities as the application authorization boundary.
3. Add Tailscale, Headscale, or NetBird only when the organization needs central device
   membership and network ACLs.
4. Add SPIRE when one host runs multiple workers that need separate identities.
5. Do not stack products without a clear boundary and an owner for each policy layer.

## Production gate

Do not enable unattended work until the open invite-binding, recovery, transactional
audit, workload identity, secret brokering, and domain egress items are complete. The
current release is suitable for supervised peer messaging and task coordination on
trusted hosts.
