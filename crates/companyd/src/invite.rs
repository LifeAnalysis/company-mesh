use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use iroh::{EndpointAddr, EndpointId, SecretKey, Signature};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityGrant {
    pub capability_id: String,
    pub kinds: Vec<String>,
    pub scope_prefixes: Vec<String>,
    pub max_messages_per_minute: u32,
}

impl CapabilityGrant {
    pub fn messages(scope_prefixes: Vec<String>, max_messages_per_minute: u32) -> Result<Self> {
        if scope_prefixes.is_empty()
            || scope_prefixes
                .iter()
                .any(|scope| !crate::model::valid_scope(scope))
        {
            bail!("at least one valid scope prefix is required");
        }
        if !(1..=600).contains(&max_messages_per_minute) {
            bail!("message rate must be between 1 and 600 per minute");
        }
        Ok(Self {
            capability_id: Uuid::new_v4().to_string(),
            kinds: vec!["message".to_owned()],
            scope_prefixes,
            max_messages_per_minute,
        })
    }

    pub fn allows(&self, capability_id: &str, kind: &str, scope: &str) -> bool {
        self.capability_id == capability_id
            && self.kinds.iter().any(|allowed| allowed == kind)
            && self
                .scope_prefixes
                .iter()
                .any(|prefix| scope.starts_with(prefix))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteClaims {
    pub protocol: String,
    pub invite_id: Uuid,
    pub organization: String,
    pub issuer_endpoint: String,
    pub issuer_addr: EndpointAddr,
    pub issuer_label: String,
    pub invitee_label: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub joiner_to_inviter: CapabilityGrant,
    pub inviter_to_joiner: CapabilityGrant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedInvite {
    pub claims: InviteClaims,
    pub signature: String,
}

impl SignedInvite {
    pub fn issue(secret: &SecretKey, claims: InviteClaims) -> Result<Self> {
        if claims.issuer_endpoint != secret.public().to_string() {
            bail!("invite issuer does not match the signing key");
        }
        let signature =
            URL_SAFE_NO_PAD.encode(secret.sign(&serde_json::to_vec(&claims)?).to_bytes());
        Ok(Self { claims, signature })
    }

    pub fn encode(&self) -> Result<String> {
        Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(self)?))
    }

    pub fn decode(token: &str) -> Result<Self> {
        let bytes = URL_SAFE_NO_PAD
            .decode(token)
            .context("decode invite token")?;
        let invite: Self = serde_json::from_slice(&bytes).context("parse invite token")?;
        invite.verify(Utc::now())?;
        Ok(invite)
    }

    pub fn verify(&self, now: DateTime<Utc>) -> Result<()> {
        if self.claims.protocol != crate::model::PROTOCOL {
            bail!("unsupported invite protocol");
        }
        if self.claims.expires_at < now
            || self.claims.issued_at > now + chrono::Duration::minutes(5)
        {
            bail!("invite is expired or not yet valid");
        }
        if self.claims.issuer_addr.id.to_string() != self.claims.issuer_endpoint {
            bail!("invite address does not match its issuer");
        }
        let issuer = EndpointId::from_str(&self.claims.issuer_endpoint)
            .context("invalid invite issuer endpoint")?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .context("decode invite signature")?;
        let bytes: [u8; Signature::LENGTH] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid invite signature length"))?;
        issuer
            .verify(
                &serde_json::to_vec(&self.claims)?,
                &Signature::from_bytes(&bytes),
            )
            .map_err(|_| anyhow::anyhow!("invalid invite signature"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_invite_round_trips_and_rejects_tampering() {
        let secret = SecretKey::generate();
        let now = Utc::now();
        let claims = InviteClaims {
            protocol: crate::model::PROTOCOL.to_owned(),
            invite_id: Uuid::new_v4(),
            organization: "acme".to_owned(),
            issuer_endpoint: secret.public().to_string(),
            issuer_addr: EndpointAddr::new(secret.public()),
            issuer_label: "alice".to_owned(),
            invitee_label: "friend".to_owned(),
            issued_at: now,
            expires_at: now + chrono::Duration::hours(1),
            joiner_to_inviter: CapabilityGrant::messages(vec!["project:mesh".into()], 10).unwrap(),
            inviter_to_joiner: CapabilityGrant::messages(vec!["project:mesh".into()], 10).unwrap(),
        };
        let token = SignedInvite::issue(&secret, claims)
            .unwrap()
            .encode()
            .unwrap();
        let mut decoded = SignedInvite::decode(&token).unwrap();
        decoded.claims.organization = "evil".to_owned();
        assert!(decoded.verify(Utc::now()).is_err());
    }
}
