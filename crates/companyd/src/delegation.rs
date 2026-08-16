use std::{collections::BTreeMap, str::FromStr};

use anyhow::{Context, Result, bail};
use biscuit_auth::{
    Biscuit, KeyPair, PrivateKey, PublicKey,
    builder::{Algorithm, AuthorizerBuilder},
};
use cedar_policy::{
    Authorizer, Context as CedarContext, Decision, Entities, EntityUid, PolicySet, Request,
};
use chrono::{DateTime, Utc};
use iroh::{EndpointId, SecretKey};
use serde::{Deserialize, Serialize};
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
    #[serde(default)]
    pub cedar_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceCapabilityClaims {
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

/// A standard Biscuit capability. The claims are recovered from signed Biscuit facts;
/// they are not a parallel custom token format.
#[derive(Debug, Clone)]
pub struct ServiceCapability {
    pub claims: ServiceCapabilityClaims,
    token: String,
}

impl ServiceCapability {
    pub fn issue(secret: &SecretKey, claims: ServiceCapabilityClaims) -> Result<Self> {
        Self::issue_at(secret, claims, Utc::now())
    }

    fn issue_at(
        secret: &SecretKey,
        claims: ServiceCapabilityClaims,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        if claims.issuer_endpoint != secret.public().to_string() {
            bail!("service capability issuer does not match signing key");
        }
        validate_claims(&claims, now)?;
        let private = PrivateKey::from_bytes(&secret.to_bytes(), Algorithm::Ed25519)
            .context("derive Biscuit signing key from Iroh identity")?;
        let root = KeyPair::from(&private);
        let mut facts = format!(
            "grant_id({}); issuer({}); grantee({}); service({}); project({}); issued_at({}); expires_at({}); max_calls({});",
            quoted(&claims.grant_id.to_string()),
            quoted(&claims.issuer_endpoint),
            quoted(&claims.grantee_endpoint),
            quoted(&claims.service),
            quoted(&claims.project),
            claims.issued_at.timestamp(),
            claims.expires_at.timestamp(),
            claims.max_calls,
        );
        for operation in &claims.operations {
            facts.push_str(&format!(
                " right({}, {});",
                quoted(&claims.service),
                quoted(operation)
            ));
        }
        let token = Biscuit::builder().code(facts)?.build(&root)?.to_base64()?;
        Ok(Self { claims, token })
    }

    pub fn encode(&self) -> &str {
        &self.token
    }

    pub fn decode(token: &str, issuer_endpoint: &str, now: DateTime<Utc>) -> Result<Self> {
        let issuer = EndpointId::from_str(issuer_endpoint).context("parse capability issuer")?;
        let root = PublicKey::from_bytes(issuer.as_bytes(), Algorithm::Ed25519)
            .context("convert Iroh endpoint to Biscuit verification key")?;
        let biscuit = Biscuit::from_base64(token, root).context("verify Biscuit capability")?;
        let mut authorizer = biscuit.authorizer()?;
        let grant_id: (String,) = authorizer.query_exactly_one("data($v) <- grant_id($v)")?;
        let issuer_fact: (String,) = authorizer.query_exactly_one("data($v) <- issuer($v)")?;
        let grantee: (String,) = authorizer.query_exactly_one("data($v) <- grantee($v)")?;
        let service: (String,) = authorizer.query_exactly_one("data($v) <- service($v)")?;
        let project: (String,) = authorizer.query_exactly_one("data($v) <- project($v)")?;
        let issued_at: (i64,) = authorizer.query_exactly_one("data($v) <- issued_at($v)")?;
        let expires_at: (i64,) = authorizer.query_exactly_one("data($v) <- expires_at($v)")?;
        let max_calls: (i64,) = authorizer.query_exactly_one("data($v) <- max_calls($v)")?;
        let operation_query = format!(
            "data($operation) <- right({}, $operation)",
            quoted(&service.0)
        );
        let mut operations: Vec<String> = authorizer
            .query::<_, (String,), biscuit_auth::error::Token>(operation_query.as_str())?
            .into_iter()
            .map(|value| value.0)
            .collect();
        operations.sort();
        operations.dedup();
        let claims = ServiceCapabilityClaims {
            grant_id: Uuid::parse_str(&grant_id.0).context("parse capability grant id")?,
            issuer_endpoint: issuer_fact.0,
            grantee_endpoint: grantee.0,
            service: service.0,
            project: project.0,
            operations,
            issued_at: DateTime::from_timestamp(issued_at.0, 0)
                .context("invalid capability issue time")?,
            expires_at: DateTime::from_timestamp(expires_at.0, 0)
                .context("invalid capability expiry")?,
            max_calls: u32::try_from(max_calls.0).context("invalid capability call limit")?,
        };
        if claims.issuer_endpoint != issuer_endpoint {
            bail!("Biscuit capability issuer fact does not match its signing key");
        }
        validate_claims(&claims, now)?;
        Ok(Self {
            claims,
            token: token.to_owned(),
        })
    }

    pub fn authorize_call(
        &self,
        remote_endpoint: &str,
        service: &str,
        project: &str,
        operation: &str,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let mut authorizer = AuthorizerBuilder::new()
            .code(format!(
                r#"
                ambient_grantee({});
                ambient_service({});
                ambient_project({});
                ambient_operation({});
                ambient_time({});
                allow if grantee($g), ambient_grantee($g),
                    service($s), ambient_service($s),
                    project($p), ambient_project($p),
                    right($s, $o), ambient_operation($o),
                    issued_at($start), expires_at($end), ambient_time($now),
                    $start <= $now, $now < $end;
                deny if true;
                "#,
                quoted(remote_endpoint),
                quoted(service),
                quoted(project),
                quoted(operation),
                now.timestamp()
            ))?
            .build(&Biscuit::from_base64(
                &self.token,
                PublicKey::from_bytes(
                    EndpointId::from_str(&self.claims.issuer_endpoint)?.as_bytes(),
                    Algorithm::Ed25519,
                )?,
            )?)?;
        authorizer
            .authorize()
            .map(|_| ())
            .context("Biscuit capability denied service call")
    }
}

pub fn generated_service_policy(service: &str, operations: impl Iterator<Item = String>) -> String {
    operations
        .map(|operation| {
            format!(
                "permit(principal, action == Action::{}, resource == Service::{});",
                quoted(&operation),
                quoted(service)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn authorize_with_cedar(
    policy: &str,
    peer: &str,
    service: &str,
    operation: &str,
) -> Result<()> {
    let policies = PolicySet::from_str(policy).context("parse delegated service Cedar policy")?;
    let request = Request::new(
        entity_uid("Peer", peer)?,
        entity_uid("Action", operation)?,
        entity_uid("Service", service)?,
        CedarContext::empty(),
        None,
    )?;
    let response = Authorizer::new().is_authorized(&request, &policies, &Entities::empty());
    if response.decision() != Decision::Allow {
        bail!("Cedar policy denied delegated service call");
    }
    Ok(())
}

fn entity_uid(kind: &str, id: &str) -> Result<EntityUid> {
    EntityUid::from_str(&format!("{kind}::{}", quoted(id))).map_err(Into::into)
}

fn quoted(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a string cannot fail")
}

fn validate_claims(claims: &ServiceCapabilityClaims, now: DateTime<Utc>) -> Result<()> {
    if claims.service.is_empty()
        || claims.project.is_empty()
        || claims.operations.is_empty()
        || !(1..=100).contains(&claims.max_calls)
        || claims.expires_at <= now
        || claims.issued_at > now + chrono::Duration::minutes(5)
    {
        bail!("invalid or expired service capability");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn claims(
        secret: &SecretKey,
        grantee: &SecretKey,
        now: DateTime<Utc>,
    ) -> ServiceCapabilityClaims {
        ServiceCapabilityClaims {
            grant_id: Uuid::from_u128(7),
            issuer_endpoint: secret.public().to_string(),
            grantee_endpoint: grantee.public().to_string(),
            service: "source-index".to_owned(),
            project: "mesh".to_owned(),
            operations: vec!["inspect".to_owned()],
            issued_at: now,
            expires_at: now + chrono::Duration::minutes(10),
            max_calls: 2,
        }
    }

    #[test]
    fn biscuit_capability_is_bound_to_peer_project_service_operation_and_time() {
        let now = Utc.with_ymd_and_hms(2026, 8, 16, 12, 0, 0).unwrap();
        let issuer = SecretKey::from_bytes(&[1; 32]);
        let grantee = SecretKey::from_bytes(&[2; 32]);
        let capability =
            ServiceCapability::issue_at(&issuer, claims(&issuer, &grantee, now), now).unwrap();
        let decoded =
            ServiceCapability::decode(capability.encode(), &issuer.public().to_string(), now)
                .unwrap();
        assert_eq!(decoded.claims, claims(&issuer, &grantee, now));
        decoded
            .authorize_call(
                &grantee.public().to_string(),
                "source-index",
                "mesh",
                "inspect",
                now,
            )
            .unwrap();
        assert!(
            decoded
                .authorize_call(
                    &grantee.public().to_string(),
                    "source-index",
                    "other",
                    "inspect",
                    now
                )
                .is_err()
        );
        assert!(
            decoded
                .authorize_call(
                    &grantee.public().to_string(),
                    "source-index",
                    "mesh",
                    "write",
                    now
                )
                .is_err()
        );
        assert!(
            decoded
                .authorize_call(
                    &grantee.public().to_string(),
                    "source-index",
                    "mesh",
                    "inspect",
                    now + chrono::Duration::minutes(10)
                )
                .is_err()
        );
    }

    #[test]
    fn cedar_has_default_deny_and_allows_only_registered_operations() {
        let policy = generated_service_policy("source-index", ["inspect".to_owned()].into_iter());
        authorize_with_cedar(&policy, "peer-a", "source-index", "inspect").unwrap();
        assert!(authorize_with_cedar(&policy, "peer-a", "source-index", "write").is_err());
        assert!(authorize_with_cedar("", "peer-a", "source-index", "inspect").is_err());
    }
}
