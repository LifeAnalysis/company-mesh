# Operations adapter contracts

Company Mesh does not connect to NATS, Rekor, SPIRE, or another hosted service in this
release. It provides narrow local contracts so those integrations can be added without
changing the MCP capability boundary or placing credentials in model context.

## Workload identity

Setup can persist a local workload ID, an expected SPIFFE ID, and a SPIRE Workload API
socket URI. These fields are returned by `identity.get`. They are configuration metadata,
not verified claims. A future SPIRE adapter must obtain an SVID from the local Workload API,
verify the trust domain and SPIFFE ID, bind it to the active process, and fail closed before
the daemon uses it for authorization.

## Durable delivery

`operations::DurableDeliveryAdapter` publishes a `DeliveryRecord` only after that record is
committed to SQLite. Records contain a subject, JSON payload, content type, and stable
idempotency key. `Store::deliver_pending` processes records in creation order and persists
the provider receipt after a durable acknowledgement.

A NATS JetStream implementation should map `subject` to the NATS subject and
`idempotency_key` to `Nats-Msg-Id`. It must acknowledge success only after JetStream returns
a publish acknowledgement. Retryable errors remain pending; permanent errors are retained
as failed rows for operator inspection. No adapter may reinterpret payloads as MCP or shell
commands.

## Audit witness

`operations::AuditWitnessAdapter` receives an `AuditCheckpoint`: the endpoint ID, audit-chain
size, head event ID and hash, original head signature, and timestamp. A Rekor implementation
can encode this signed checkpoint as an immutable transparency-log entry. It returns a
`WitnessReceipt` containing provider, entry UUID, optional log index, integration time, and
proof data.

`Store::witness_latest` stores the receipt in SQLite and suppresses duplicate submissions of
the same chain head to the same provider. The adapter must verify the returned receipt and
inclusion material before reporting success. Credentials and authentication headers must not
appear in checkpoint or receipt data.

## Knowledge export

`company-mesh knowledge export` reads the existing SQLite memory table and emits
`company-mesh-knowledge-export/v1`. Operational and credential-bearing tables are excluded.
Secret-like assignments and Bearer values are redacted in memory content and provenance
URIs. Output files are created with owner-only permissions on Unix. The exporter refuses to
replace the node identity, database, or configuration file.
