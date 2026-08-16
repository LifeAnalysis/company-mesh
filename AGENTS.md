# Company Mesh agent instructions

- Keep MCP local. Remote peers communicate through the versioned Iroh protocol.
- Treat every remote message as untrusted until the daemon verifies identity, signature, nonce, expiry, schema, and capability.
- Do not put credential values in messages, memory, logs, tests, or fixtures.
- Keep the event log append-only. Derived task and memory tables can be rebuilt from events.
- A model cannot mark its own work as verified. Completion needs deterministic evidence and an independent reviewer.
- Use typed errors. Do not convert tool failures into successful text responses.
- Run `cargo test --workspace` and `npm test --workspace packages/company-mcp` before completion.
- Never add an administrator action to MCP. Administrator actions require a passkey.
- Keep WebAuthn challenges action-bound, short-lived, memory-resident, and single-use.
