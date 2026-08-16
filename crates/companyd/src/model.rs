use std::str::FromStr;

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use iroh::{EndpointId, SecretKey, Signature};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub const PROTOCOL: &str = "company.mesh/1";
pub const ALPN: &[u8] = b"company.mesh/1";
pub const MAX_ENVELOPE_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub protocol: String,
    pub message_id: Uuid,
    pub correlation_id: Option<Uuid>,
    pub sender_endpoint: String,
    pub sender_agent: String,
    pub kind: String,
    pub scope: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub nonce: String,
    pub capability_ref: Option<String>,
    pub payload_hash: String,
    pub payload: Value,
    pub signature: String,
}

#[derive(Serialize)]
struct SigningMaterial<'a> {
    protocol: &'a str,
    message_id: Uuid,
    correlation_id: Option<Uuid>,
    sender_endpoint: &'a str,
    sender_agent: &'a str,
    kind: &'a str,
    scope: &'a str,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    nonce: &'a str,
    capability_ref: &'a Option<String>,
    payload_hash: &'a str,
}

impl Envelope {
    pub fn new(
        secret: &SecretKey,
        sender_agent: impl Into<String>,
        kind: impl Into<String>,
        scope: impl Into<String>,
        payload: Value,
    ) -> Result<Self> {
        Self::new_with_capability(secret, sender_agent, kind, scope, payload, None)
    }

    pub fn new_with_capability(
        secret: &SecretKey,
        sender_agent: impl Into<String>,
        kind: impl Into<String>,
        scope: impl Into<String>,
        payload: Value,
        capability_ref: Option<String>,
    ) -> Result<Self> {
        let issued_at = Utc::now();
        let payload_hash = blake3::hash(&serde_json::to_vec(&payload)?)
            .to_hex()
            .to_string();
        let mut envelope = Self {
            protocol: PROTOCOL.to_owned(),
            message_id: Uuid::new_v4(),
            correlation_id: None,
            sender_endpoint: secret.public().to_string(),
            sender_agent: sender_agent.into(),
            kind: kind.into(),
            scope: scope.into(),
            issued_at,
            expires_at: issued_at + Duration::minutes(10),
            nonce: Uuid::new_v4().simple().to_string(),
            capability_ref,
            payload_hash,
            payload,
            signature: String::new(),
        };
        envelope.validate_shape()?;
        let signature = secret.sign(&envelope.signing_bytes()?);
        envelope.signature = STANDARD_NO_PAD.encode(signature.to_bytes());
        Ok(envelope)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&SigningMaterial {
            protocol: &self.protocol,
            message_id: self.message_id,
            correlation_id: self.correlation_id,
            sender_endpoint: &self.sender_endpoint,
            sender_agent: &self.sender_agent,
            kind: &self.kind,
            scope: &self.scope,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            nonce: &self.nonce,
            capability_ref: &self.capability_ref,
            payload_hash: &self.payload_hash,
        })?)
    }

    pub fn verify(&self, authenticated_remote: EndpointId, now: DateTime<Utc>) -> Result<()> {
        self.validate_shape()?;
        if self.sender_endpoint != authenticated_remote.to_string() {
            bail!("sender endpoint does not match the authenticated Iroh peer");
        }
        if self.expires_at < now {
            bail!("envelope expired");
        }
        if self.issued_at > now + Duration::minutes(5) {
            bail!("envelope issue time is too far in the future");
        }
        let actual_payload_hash = blake3::hash(&serde_json::to_vec(&self.payload)?)
            .to_hex()
            .to_string();
        if self.payload_hash != actual_payload_hash {
            bail!("payload hash mismatch");
        }
        let endpoint_id =
            EndpointId::from_str(&self.sender_endpoint).context("invalid sender endpoint ID")?;
        let signature_bytes = STANDARD_NO_PAD
            .decode(&self.signature)
            .context("invalid signature encoding")?;
        let signature_bytes: [u8; Signature::LENGTH] = signature_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid signature length"))?;
        let signature = Signature::from_bytes(&signature_bytes);
        endpoint_id
            .verify(&self.signing_bytes()?, &signature)
            .map_err(|_| anyhow::anyhow!("invalid envelope signature"))?;
        Ok(())
    }

    fn validate_shape(&self) -> Result<()> {
        if self.protocol != PROTOCOL {
            bail!("unsupported protocol version");
        }
        if self.sender_agent.is_empty() || self.sender_agent.len() > 128 {
            bail!("invalid sender agent");
        }
        if !valid_scope(&self.scope) {
            bail!("scope must start with task:, project:, team:, or company:");
        }
        if !matches!(
            self.kind.as_str(),
            "message"
                | "task_offer"
                | "task_result"
                | "memory_episode"
                | "receipt"
                | "enrollment_request"
        ) {
            bail!("unsupported envelope kind");
        }
        if self.nonce.len() < 16 {
            bail!("nonce is too short");
        }
        Ok(())
    }
}

pub fn valid_scope(scope: &str) -> bool {
    ["task:", "project:", "team:", "company:"]
        .iter()
        .any(|prefix| scope.starts_with(prefix) && scope.len() > prefix.len())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Ack {
    pub ok: bool,
    pub message_id: Uuid,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
    #[serde(default = "default_agent")]
    pub agent_id: String,
    #[serde(default)]
    pub approval: Option<crate::passkey::AdminApproval>,
}

fn default_agent() -> String {
    "local-agent".to_owned()
}

#[derive(Debug, Serialize)]
pub struct RpcResponse {
    pub id: Value,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
pub struct RpcError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

impl RpcResponse {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            id,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn failure(id: Value, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            result: None,
            error: Some(RpcError {
                code: code.into(),
                message: message.into(),
                retryable: false,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_envelope_verifies_and_tampering_fails() {
        let key = SecretKey::generate();
        let mut envelope = Envelope::new(
            &key,
            "agent:test",
            "message",
            "project:test",
            serde_json::json!({"text": "hello"}),
        )
        .unwrap();
        envelope.verify(key.public(), Utc::now()).unwrap();
        envelope.payload = serde_json::json!({"text": "changed"});
        assert!(envelope.verify(key.public(), Utc::now()).is_err());
    }
}
