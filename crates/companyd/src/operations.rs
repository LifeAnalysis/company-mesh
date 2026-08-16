use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One persisted message awaiting delivery by a durable transport such as NATS JetStream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeliveryRecord {
    pub delivery_id: String,
    pub subject: String,
    pub payload: Value,
    pub content_type: String,
    pub idempotency_key: String,
    pub attempts: u32,
    pub created_at: String,
}

/// Transport acknowledgement. `sequence` can hold a JetStream stream sequence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeliveryReceipt {
    pub provider: String,
    pub sequence: Option<u64>,
    pub acknowledged_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for AdapterError {}

/// Boundary implemented by an optional durable transport adapter.
///
/// Implementations must use `idempotency_key` for de-duplication and return only after
/// the broker has durably acknowledged the message.
pub trait DurableDeliveryAdapter {
    fn publish(&mut self, message: &DeliveryRecord) -> Result<DeliveryReceipt, AdapterError>;
}

/// Signed head of the local append-only audit chain, suitable as a Rekor entry body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditCheckpoint {
    pub protocol: String,
    pub endpoint_id: String,
    pub chain_size: i64,
    pub event_id: String,
    pub head_hash: String,
    pub head_signature: String,
    pub created_at: String,
}

/// Provider receipt. A Rekor adapter can store its UUID, log index, integrated time,
/// and inclusion proof in these fields without leaking credentials into the database.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WitnessReceipt {
    pub provider: String,
    pub entry_id: String,
    pub log_index: Option<u64>,
    pub integrated_at: String,
    pub proof: Value,
}

/// Boundary implemented by an optional transparency-log witness such as Rekor.
pub trait AuditWitnessAdapter {
    fn provider(&self) -> &str;
    fn witness(&mut self, checkpoint: &AuditCheckpoint) -> Result<WitnessReceipt, AdapterError>;
}
