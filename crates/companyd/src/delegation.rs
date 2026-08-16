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
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDefinition {
    pub name: String,
    pub executable: String,
    #[serde(default)]
    pub executable_hash: String,
    pub operations: BTreeMap<String, ServiceOperation>,
    pub timeout_seconds: u64,
    pub max_output_bytes: usize,
    #[serde(default)]
    pub allow_network: bool,
    #[serde(default)]
    pub read_only_paths: Vec<String>,
    #[serde(default)]
    pub cedar_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServiceOperation {
    Legacy(Vec<String>),
    Typed {
        arguments: Vec<String>,
        #[serde(default)]
        parameters: BTreeMap<String, ParameterRule>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterRule {
    #[serde(rename = "type", default)]
    pub kind: ParameterKind,
    #[serde(default = "required_by_default")]
    pub required: bool,
    #[serde(default)]
    pub allowed_values: Vec<String>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default = "default_parameter_length")]
    pub max_length: usize,
    #[serde(default)]
    pub allow_leading_hyphen: bool,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParameterKind {
    #[default]
    String,
    Integer,
    Boolean,
}

impl ServiceOperation {
    pub fn validate(&self) -> Result<()> {
        let (arguments, parameters) = self.parts();
        if arguments.is_empty() || arguments.len() > 64 {
            bail!("service operation must contain 1 to 64 fixed arguments");
        }
        if parameters.len() > 20 {
            bail!("service operation can define at most 20 parameters");
        }
        for (name, rule) in parameters {
            if name == "project" || !valid_parameter_name(name) {
                bail!("invalid or reserved delegated parameter name");
            }
            if !(1..=4096).contains(&rule.max_length)
                || !rule.required
                || rule.allowed_values.len() > 100
                || rule
                    .allowed_values
                    .iter()
                    .any(|value| validate_parameter_text(value, rule).is_err())
                || rule.pattern.as_ref().is_some_and(|pattern| {
                    pattern.len() > 256 || regex::Regex::new(pattern).is_err()
                })
            {
                bail!("invalid delegated parameter rule for {name}");
            }
        }
        let mut used = std::collections::BTreeSet::new();
        for argument in arguments {
            if argument.len() > 4096 {
                bail!("delegated argument template is too long");
            }
            for placeholder in placeholders(argument)? {
                if placeholder != "project" && !parameters.contains_key(&placeholder) {
                    bail!("argument uses undefined delegated parameter {placeholder}");
                }
                used.insert(placeholder);
            }
        }
        if parameters.keys().any(|name| !used.contains(name)) {
            bail!("every delegated parameter must appear in an argument template");
        }
        Ok(())
    }

    pub fn render(&self, project: &str, supplied: &Value) -> Result<Vec<String>> {
        let (arguments, rules) = self.parts();
        let supplied = supplied
            .as_object()
            .context("delegated parameters must be a JSON object")?;
        if matches!(self, Self::Legacy(_)) && !supplied.is_empty() {
            bail!("this legacy operation does not accept parameters");
        }
        if supplied.keys().any(|name| !rules.contains_key(name)) {
            bail!("delegated call contains an unknown parameter");
        }
        let mut values = BTreeMap::from([("project".to_owned(), project.to_owned())]);
        for (name, rule) in rules {
            let value = supplied
                .get(name)
                .with_context(|| format!("delegated call omitted required parameter {name}"))?;
            values.insert(name.clone(), render_parameter(value, rule)?);
        }
        arguments
            .iter()
            .map(|argument| {
                let mut rendered = argument.clone();
                for placeholder in placeholders(argument)? {
                    let value = values.get(&placeholder).with_context(|| {
                        format!("delegated parameter {placeholder} was not supplied")
                    })?;
                    rendered = rendered.replace(&format!("{{{placeholder}}}"), value);
                }
                Ok(rendered)
            })
            .collect()
    }

    fn parts(&self) -> (&Vec<String>, &BTreeMap<String, ParameterRule>) {
        static EMPTY: std::sync::LazyLock<BTreeMap<String, ParameterRule>> =
            std::sync::LazyLock::new(BTreeMap::new);
        match self {
            Self::Legacy(arguments) => (arguments, &EMPTY),
            Self::Typed {
                arguments,
                parameters,
            } => (arguments, parameters),
        }
    }
}

fn render_parameter(value: &Value, rule: &ParameterRule) -> Result<String> {
    let rendered = match rule.kind {
        ParameterKind::String => value
            .as_str()
            .context("delegated string parameter must be a string")?
            .to_owned(),
        ParameterKind::Integer => value
            .as_i64()
            .context("delegated integer parameter must be a signed integer")?
            .to_string(),
        ParameterKind::Boolean => value
            .as_bool()
            .context("delegated boolean parameter must be a boolean")?
            .to_string(),
    };
    validate_parameter_text(&rendered, rule)?;
    Ok(rendered)
}

fn validate_parameter_text(value: &str, rule: &ParameterRule) -> Result<()> {
    if value.is_empty()
        || value.len() > rule.max_length
        || value.chars().any(char::is_control)
        || (!rule.allow_leading_hyphen && value.starts_with('-'))
        || (!rule.allowed_values.is_empty()
            && !rule.allowed_values.iter().any(|allowed| allowed == value))
        || rule.pattern.as_ref().is_some_and(|pattern| {
            !regex::Regex::new(pattern).is_ok_and(|regex| regex.is_match(value))
        })
    {
        bail!("delegated parameter value is outside its registered rule");
    }
    Ok(())
}

fn placeholders(argument: &str) -> Result<Vec<String>> {
    let mut names = Vec::new();
    let mut remaining = argument;
    while let Some(start) = remaining.find('{') {
        if remaining[..start].contains('}') {
            bail!("invalid delegated argument placeholder");
        }
        let after = &remaining[start + 1..];
        let end = after
            .find('}')
            .context("unterminated delegated argument placeholder")?;
        let name = &after[..end];
        if !valid_parameter_name(name) {
            bail!("invalid delegated argument placeholder");
        }
        names.push(name.to_owned());
        remaining = &after[end + 1..];
    }
    if remaining.contains('}') {
        bail!("invalid delegated argument placeholder");
    }
    Ok(names)
}

fn valid_parameter_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| byte.is_ascii_alphanumeric() || byte == b'_' && index > 0)
        && value.as_bytes()[0].is_ascii_alphabetic()
}

const fn required_by_default() -> bool {
    true
}

const fn default_parameter_length() -> usize {
    256
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

pub fn validate_cedar_policy(policy: &str) -> Result<()> {
    PolicySet::from_str(policy)
        .context("parse delegated service Cedar policy")
        .map(|_| ())
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

    #[test]
    fn typed_operation_renders_only_registered_parameter_values() {
        let operation = ServiceOperation::Typed {
            arguments: vec![
                "inspect".to_owned(),
                "{project}".to_owned(),
                "--environment".to_owned(),
                "{environment}".to_owned(),
                "--limit".to_owned(),
                "{limit}".to_owned(),
            ],
            parameters: BTreeMap::from([
                (
                    "environment".to_owned(),
                    ParameterRule {
                        kind: ParameterKind::String,
                        required: true,
                        allowed_values: vec!["preview".to_owned(), "production".to_owned()],
                        pattern: None,
                        max_length: 20,
                        allow_leading_hyphen: false,
                    },
                ),
                (
                    "limit".to_owned(),
                    ParameterRule {
                        kind: ParameterKind::Integer,
                        required: true,
                        allowed_values: Vec::new(),
                        pattern: Some(r"^[1-9][0-9]?$".to_owned()),
                        max_length: 2,
                        allow_leading_hyphen: false,
                    },
                ),
            ]),
        };
        operation.validate().unwrap();
        assert_eq!(
            operation
                .render(
                    "project-a",
                    &serde_json::json!({"environment":"preview","limit":10})
                )
                .unwrap(),
            [
                "inspect",
                "project-a",
                "--environment",
                "preview",
                "--limit",
                "10"
            ]
        );
        assert!(
            operation
                .render(
                    "project-a",
                    &serde_json::json!({"environment":"invalid","limit":10})
                )
                .is_err()
        );
        assert!(
            operation
                .render(
                    "project-a",
                    &serde_json::json!({"environment":"preview","limit":10,"extra":true})
                )
                .is_err()
        );
    }
}
