# Company Mesh protocol 1

The Iroh ALPN is `company.mesh/1`.

Each connection carries one JSON envelope on one bidirectional stream. The receiver
returns one JSON acknowledgement.

The envelope includes:

- protocol version
- message and correlation IDs
- sender endpoint and agent IDs
- kind and authorization scope
- issue and expiry times
- replay nonce
- optional capability reference
- payload and BLAKE3 payload hash
- Ed25519 signature

The signature covers the canonical serialized envelope fields except the signature.
The receiver checks the signature against the authenticated Iroh remote endpoint ID.

Normal messages also require an active peer record. The receiver compares the capability
reference, message kind, and scope against that record. It then applies the peer rate limit.

`enrollment_request` is the only message accepted from an unknown endpoint. Its payload
contains a signed invitation and the joiner's current Iroh address. The invitation must be
registered by its issuer, unexpired, unused, and signed by the receiving node. Successful
enrollment consumes it and creates reciprocal capability records.

## Delegated services

Delegation control messages use the normal enrolled-peer `message` capability and a
`project:NAME` scope. A request contains only service, project, operation names, and a
reason. Approval creates a signed service grant bound to issuer endpoint, grantee
endpoint, service, project, operations, expiry, and maximum calls.

Grant tokens are stored by daemons and are redacted from inbox records. Service calls
carry the token inside the signed and encrypted Iroh envelope. The issuing daemon checks
the grant again and runs only a pre-registered executable and fixed argument template.
`{project}` is the only supported placeholder. No shell text or caller arguments exist.

Protocol 1 accepts authorized peer messages into a quarantine inbox only. It has no remote
tool invocation. Task offers, results, and memory episodes remain reserved until separate
promotion and validation rules exist.
