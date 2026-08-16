use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use iroh::{EndpointId, SecretKey, Signature};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, str::FromStr};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDefinition {
    pub name: String,
    pub executable: String,
    #[serde(default)]
    pub executable_hash: String,
    pub operations: BTreeMap<String, Vec<String>>,
    pub timeout_seconds: u64,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceGrantClaims {
    pub grant_id: Uuid,
    pub issuer_endpoint: String,
    pub grantee_endpoint: String,
    pub service: String,
    pub project: String,
    pub operations: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub max_calls: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedServiceGrant {
    pub claims: ServiceGrantClaims,
    pub signature: String,
}

impl SignedServiceGrant {
    pub fn issue(secret: &SecretKey, claims: ServiceGrantClaims) -> Result<Self> {
        if claims.issuer_endpoint != secret.public().to_string() {
            bail!("service grant issuer does not match signing key");
        }
        validate_claims(&claims, Utc::now())?;
        Ok(Self {
            signature: URL_SAFE_NO_PAD
                .encode(secret.sign(&serde_json::to_vec(&claims)?).to_bytes()),
            claims,
        })
    }

    pub fn encode(&self) -> Result<String> {
        Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(self)?))
    }

    pub fn decode(token: &str) -> Result<Self> {
        let value: Self = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(token)
                .context("decode service grant")?,
        )?;
        value.verify(Utc::now())?;
        Ok(value)
    }

    pub fn verify(&self, now: DateTime<Utc>) -> Result<()> {
        validate_claims(&self.claims, now)?;
        let issuer = EndpointId::from_str(&self.claims.issuer_endpoint)?;
        let bytes: [u8; Signature::LENGTH] = URL_SAFE_NO_PAD
            .decode(&self.signature)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid service grant signature length"))?;
        issuer
            .verify(
                &serde_json::to_vec(&self.claims)?,
                &Signature::from_bytes(&bytes),
            )
            .map_err(|_| anyhow::anyhow!("invalid service grant signature"))
    }
}

fn validate_claims(claims: &ServiceGrantClaims, now: DateTime<Utc>) -> Result<()> {
    if claims.service.is_empty()
        || claims.project.is_empty()
        || claims.operations.is_empty()
        || !(1..=100).contains(&claims.max_calls)
        || claims.expires_at <= now
        || claims.issued_at > now + chrono::Duration::minutes(5)
    {
        bail!("invalid or expired service grant");
    }
    Ok(())
}
