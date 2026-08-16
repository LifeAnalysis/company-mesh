use std::{path::Path, sync::Arc};

use anyhow::{Context, Result, bail};
use chrono::{Duration, Utc};
use iroh::{Endpoint, EndpointAddr, SecretKey};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{Mutex, Semaphore},
    task::JoinSet,
};
use tracing::warn;

use crate::{
    config::NodeConfig,
    delegation::{ServiceCapability, ServiceDefinition},
    invite::{CapabilityGrant, InviteClaims, SignedInvite},
    model::{Envelope, RpcRequest, RpcResponse},
    network::send_envelope,
    passkey::{AdminGate, SessionScope},
    store::{MemoryProposal, Store},
};

#[derive(Clone)]
pub struct AppState {
    pub node_name: String,
    pub config: NodeConfig,
    pub secret: SecretKey,
    pub endpoint: Endpoint,
    pub store: Arc<Mutex<Store>>,
    pub admin_gate: Option<Arc<Mutex<AdminGate>>>,
}

pub async fn serve_local_socket(path: &Path, state: AppState) -> Result<()> {
    if path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if !std::fs::symlink_metadata(path)?.file_type().is_socket() {
                bail!("refusing to replace non-socket path {}", path.display());
            }
        }
        std::fs::remove_file(path)
            .with_context(|| format!("remove stale socket {}", path.display()))?;
    }
    let listener = UnixListener::bind(path)
        .with_context(|| format!("bind local socket {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    let mut clients = JoinSet::new();
    let client_limit = Arc::new(Semaphore::new(32));
    loop {
        let (stream, _) = listener.accept().await?;
        let permit = client_limit.clone().acquire_owned().await?;
        let state = state.clone();
        clients.spawn(async move {
            let _permit = permit;
            serve_client(stream, state).await
        });
        while let Some(result) = clients.try_join_next() {
            if let Err(error) = result? {
                warn!(%error, "local RPC client failed");
            }
        }
    }
}

async fn serve_client(stream: UnixStream, state: AppState) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    while let Some(line) = lines.next_line().await? {
        if line.len() > 1_048_576 {
            bail!("local RPC request exceeds maximum size");
        }
        let response = match serde_json::from_str::<RpcRequest>(&line) {
            Ok(request) => handle(request, &state).await,
            Err(error) => RpcResponse::failure(Value::Null, "invalid_request", error.to_string()),
        };
        write.write_all(&serde_json::to_vec(&response)?).await?;
        write.write_all(b"\n").await?;
    }
    Ok(())
}

async fn handle(request: RpcRequest, state: &AppState) -> RpcResponse {
    let id = request.id.clone();
    match handle_inner(&request, state).await {
        Ok(value) => RpcResponse::success(id, value),
        Err(error) => RpcResponse::failure(id, classify_error(&error), error.to_string()),
    }
}

async fn handle_inner(request: &RpcRequest, state: &AppState) -> Result<Value> {
    if request.method == "admin.challenge" {
        #[derive(Deserialize)]
        struct P {
            action: String,
            #[serde(default)]
            params: Value,
        }
        let p: P = serde_json::from_value(request.params.clone())?;
        if !admin_required(&p.action) || !state.config.allows(&p.action) {
            bail!("the requested action is not an allowed administrator action");
        }
        let Some(gate) = state.admin_gate.as_ref() else {
            return Ok(json!({"development_bypass": true, "action": p.action}));
        };
        let binding = approval_binding(&p.action, &p.params)?;
        let mut challenge = gate.lock().await.begin(&binding)?;
        challenge["summary"] = Value::String(approval_summary(&p.action, &p.params));
        return Ok(challenge);
    }
    if admin_required(&request.method)
        && let Some(gate) = &state.admin_gate
    {
        let approval = request
            .approval
            .clone()
            .context("fresh administrator passkey approval is required")?;
        let binding = approval_binding(&request.method, &request.params)?;
        gate.lock().await.verify(approval, &binding)?;
    }
    if !state.config.allows(&request.method) {
        bail!(
            "permission denied: profile {:?} does not allow {}",
            state.config.permission_profile,
            request.method
        );
    }
    if let Some(scope) = session_scope(&request.method)
        && let Some(gate) = &state.admin_gate
    {
        gate.lock().await.require_agent_session(scope)?;
    }
    let actor = if state.config.allow_agent_override {
        request.agent_id.as_str()
    } else {
        state.config.agent_id.as_str()
    };
    match request.method.as_str() {
        "health" => Ok(json!({"status": "ok"})),
        "session.unlock" => {
            let Some(gate) = &state.admin_gate else {
                return Ok(json!({"unlocked": true, "development_bypass": true}));
            };
            gate.lock()
                .await
                .open_agent_session(SessionScope::Routine, state.config.session_minutes)
        }
        "session.unlock-external" => {
            let Some(gate) = &state.admin_gate else {
                return Ok(
                    json!({"unlocked": true, "scope": "external", "development_bypass": true}),
                );
            };
            gate.lock().await.open_agent_session(
                SessionScope::External,
                state.config.external_session_minutes,
            )
        }
        "session.status" => {
            let Some(gate) = &state.admin_gate else {
                return Ok(json!({
                    "routine": {"unlocked": true, "scope": "routine"},
                    "external": {"unlocked": true, "scope": "external"},
                    "development_bypass": true,
                }));
            };
            Ok(gate.lock().await.session_status())
        }
        "session.lock" => {
            let Some(gate) = &state.admin_gate else {
                return Ok(json!({
                    "routine": {"unlocked": false, "scope": "routine"},
                    "external": {"unlocked": false, "scope": "external"},
                    "development_bypass": true,
                }));
            };
            Ok(gate.lock().await.lock_agent_sessions())
        }
        "services.register" => {
            let definition: ServiceDefinition = serde_json::from_value(request.params.clone())?;
            state
                .store
                .lock()
                .await
                .register_service(actor, &definition)
        }
        "delegations.request" => {
            #[derive(Deserialize)]
            struct P {
                endpoint_addr: EndpointAddr,
                service: String,
                project: String,
                operations: Vec<String>,
                reason: String,
            }
            let p: P = serde_json::from_value(request.params.clone())?;
            if p.service.is_empty()
                || p.project.is_empty()
                || p.operations.is_empty()
                || p.reason.is_empty()
            {
                bail!("service, project, operations, and reason are required");
            }
            let scope = format!("project:{}", p.project);
            let peer = state.store.lock().await.authorize_outbound(
                &p.endpoint_addr.id.to_string(),
                "message",
                &scope,
            )?;
            let envelope = Envelope::new_with_capability(
                &state.secret,
                actor,
                "message",
                scope,
                json!({"type":"delegation_request","service":p.service,"project":p.project,"operations":p.operations,"reason":p.reason}),
                Some(peer.outbound.capability_id),
            )?;
            let ack = send_envelope(&state.endpoint, peer.endpoint_addr, &envelope).await?;
            if !ack.ok {
                bail!(
                    "peer rejected delegation request: {}",
                    ack.error.unwrap_or_default()
                );
            }
            Ok(json!({"request_id": envelope.message_id, "acknowledged": true}))
        }
        "delegations.approve" => {
            #[derive(Deserialize)]
            struct P {
                request_id: String,
                operations: Vec<String>,
                expires_minutes: i64,
                max_calls: u32,
            }
            let p: P = serde_json::from_value(request.params.clone())?;
            let (peer, token, details) = state.store.lock().await.issue_service_grant(
                actor,
                &p.request_id,
                &p.operations,
                p.expires_minutes,
                p.max_calls,
            )?;
            let scope = format!(
                "project:{}",
                details["project"]
                    .as_str()
                    .context("grant omitted project")?
            );
            let envelope = Envelope::new_with_capability(
                &state.secret,
                actor,
                "message",
                scope,
                json!({"type":"service_grant","token":token}),
                Some(peer.outbound.capability_id),
            )?;
            let ack = send_envelope(&state.endpoint, peer.endpoint_addr, &envelope).await?;
            if !ack.ok {
                bail!(
                    "peer rejected service grant: {}",
                    ack.error.unwrap_or_default()
                );
            }
            Ok(details)
        }
        "delegations.revoke" => {
            #[derive(Deserialize)]
            struct P {
                grant_id: String,
            }
            let p: P = serde_json::from_value(request.params.clone())?;
            state
                .store
                .lock()
                .await
                .revoke_service_grant(actor, &p.grant_id)
        }
        "services.grants" => {
            Ok(json!({"result": state.store.lock().await.received_service_grants()?}))
        }
        "services.call" => {
            #[derive(Deserialize)]
            struct P {
                grant_id: String,
                operation: String,
                #[serde(default = "empty_object")]
                parameters: Value,
            }
            let p: P = serde_json::from_value(request.params.clone())?;
            let (token, issuer_endpoint) =
                state.store.lock().await.received_grant_token(&p.grant_id)?;
            let grant = ServiceCapability::decode(&token, &issuer_endpoint, Utc::now())?;
            let peer = state
                .store
                .lock()
                .await
                .peer(&grant.claims.issuer_endpoint)?
                .context("grant issuer is not enrolled")?;
            let scope = format!("project:{}", grant.claims.project);
            let envelope = Envelope::new_with_capability(
                &state.secret,
                actor,
                "message",
                scope,
                json!({
                    "type":"service_request",
                    "grant_token":token,
                    "operation":p.operation,
                    "parameters":p.parameters,
                }),
                Some(peer.outbound.capability_id),
            )?;
            let ack = send_envelope(&state.endpoint, peer.endpoint_addr, &envelope).await?;
            if !ack.ok {
                bail!(
                    "delegated service failed: {}",
                    ack.error.unwrap_or_default()
                );
            }
            Ok(ack.result.unwrap_or(Value::Null))
        }
        "identity.get" => Ok(json!({
            "node_name": state.node_name,
            "endpoint_id": state.endpoint.id().to_string(),
            "endpoint_addr": state.endpoint.addr(),
            "protocol": crate::model::PROTOCOL,
            "organization": state.config.organization,
            "agent_id": state.config.agent_id,
            "workload_identity": state.config.workload_identity,
            "permission_profile": state.config.permission_profile,
            "enabled_actions": state.config.enabled_actions,
        })),
        "invites.create" => {
            #[derive(Deserialize)]
            struct P {
                invitee_label: String,
                scopes: Vec<String>,
                rate_per_minute: u32,
                expires_hours: i64,
            }
            let p: P = serde_json::from_value(request.params.clone())?;
            if p.invitee_label.trim().is_empty() || !(1..=168).contains(&p.expires_hours) {
                bail!("invitee label is required and expiry must be between 1 and 168 hours");
            }
            let now = Utc::now();
            let invite = SignedInvite::issue(
                &state.secret,
                InviteClaims {
                    protocol: crate::model::PROTOCOL.to_owned(),
                    invite_id: uuid::Uuid::new_v4(),
                    organization: state.config.organization.clone(),
                    issuer_endpoint: state.endpoint.id().to_string(),
                    issuer_addr: state.endpoint.addr(),
                    issuer_label: state.config.node_name.clone(),
                    invitee_label: p.invitee_label,
                    issued_at: now,
                    expires_at: now + Duration::hours(p.expires_hours),
                    joiner_to_inviter: CapabilityGrant::messages(
                        p.scopes.clone(),
                        p.rate_per_minute,
                    )?,
                    inviter_to_joiner: CapabilityGrant::messages(p.scopes, p.rate_per_minute)?,
                },
            )?;
            let token = invite.encode()?;
            let details = state.store.lock().await.register_invite(actor, &token)?;
            Ok(json!({"token": token, "invite": details}))
        }
        "peers.join" => {
            #[derive(Deserialize)]
            struct P {
                token: String,
            }
            let p: P = serde_json::from_value(request.params.clone())?;
            let invite = SignedInvite::decode(&p.token)?;
            if invite.claims.organization != state.config.organization {
                bail!("invite organization does not match local setup");
            }
            let enrollment = Envelope::new(
                &state.secret,
                actor,
                "enrollment_request",
                "company:peers",
                json!({"invite_token": p.token, "endpoint_addr": state.endpoint.addr()}),
            )?;
            let ack = send_envelope(
                &state.endpoint,
                invite.claims.issuer_addr.clone(),
                &enrollment,
            )
            .await?;
            if !ack.ok {
                bail!(
                    "invite issuer rejected enrollment: {}",
                    ack.error.unwrap_or_else(|| "unknown error".to_owned())
                );
            }
            let peer = state.store.lock().await.trust_inviter(actor, &invite)?;
            Ok(serde_json::to_value(peer)?)
        }
        "peers.list" => Ok(serde_json::to_value(
            state.store.lock().await.list_peers()?,
        )?),
        "peers.block" | "peers.unblock" | "peers.revoke" => {
            #[derive(Deserialize)]
            struct P {
                endpoint_id: String,
            }
            let p: P = serde_json::from_value(request.params.clone())?;
            let status = match request.method.as_str() {
                "peers.block" => "blocked",
                "peers.unblock" => "active",
                _ => "revoked",
            };
            state
                .store
                .lock()
                .await
                .set_peer_status(actor, &p.endpoint_id, status)
        }
        "tasks.create" => {
            #[derive(Deserialize)]
            struct P {
                task_id: String,
                title: String,
                project: String,
                #[serde(default)]
                depends_on: Vec<String>,
                #[serde(default)]
                parallel_safe: bool,
            }
            let p: P = serde_json::from_value(request.params.clone())?;
            state.store.lock().await.create_task(
                actor,
                &p.task_id,
                &p.title,
                &p.project,
                &p.depends_on,
                p.parallel_safe,
            )
        }
        "tasks.ready" => {
            #[derive(Deserialize)]
            struct P {
                project: Option<String>,
            }
            let p: P =
                serde_json::from_value(request.params.clone()).unwrap_or(P { project: None });
            Ok(serde_json::to_value(
                state.store.lock().await.ready_tasks(p.project.as_deref())?,
            )?)
        }
        "tasks.claim" => {
            #[derive(Deserialize)]
            struct P {
                task_id: String,
            }
            let p: P = serde_json::from_value(request.params.clone())?;
            state.store.lock().await.claim_task(actor, &p.task_id)
        }
        "tasks.submit" => {
            #[derive(Deserialize)]
            struct P {
                task_id: String,
                tests_passed: bool,
                review_id: String,
                commit: String,
            }
            let p: P = serde_json::from_value(request.params.clone())?;
            state.store.lock().await.submit_task(
                actor,
                &p.task_id,
                p.tests_passed,
                &p.review_id,
                &p.commit,
            )
        }
        "reviews.record" => {
            #[derive(Deserialize)]
            struct P {
                task_id: String,
                approved: bool,
                artifact: String,
            }
            let p: P = serde_json::from_value(request.params.clone())?;
            state
                .store
                .lock()
                .await
                .record_review(actor, &p.task_id, p.approved, &p.artifact)
        }
        "memory.propose" => {
            #[derive(Deserialize)]
            struct P {
                scope: String,
                kind: String,
                content: String,
                source_uri: String,
                valid_from: Option<String>,
                supersedes: Option<String>,
            }
            let p: P = serde_json::from_value(request.params.clone())?;
            state.store.lock().await.propose_memory(
                actor,
                MemoryProposal {
                    scope: &p.scope,
                    kind: &p.kind,
                    content: &p.content,
                    source_uri: &p.source_uri,
                    valid_from: p.valid_from.as_deref(),
                    supersedes: p.supersedes.as_deref(),
                },
            )
        }
        "memory.search" => {
            #[derive(Deserialize)]
            struct P {
                scope: String,
                query: String,
                limit: Option<usize>,
            }
            let p: P = serde_json::from_value(request.params.clone())?;
            Ok(serde_json::to_value(
                state.store.lock().await.search_memory(
                    &p.scope,
                    &p.query,
                    p.limit.unwrap_or(10),
                )?,
            )?)
        }
        "peer.send" => {
            #[derive(Deserialize)]
            struct P {
                endpoint_addr: EndpointAddr,
                scope: String,
                message: String,
            }
            let p: P = serde_json::from_value(request.params.clone())?;
            if p.message.trim().is_empty() || p.message.len() > 100_000 {
                bail!("message must contain 1 to 100000 characters");
            }
            let peer = state.store.lock().await.authorize_outbound(
                &p.endpoint_addr.id.to_string(),
                "message",
                &p.scope,
            )?;
            let envelope = Envelope::new_with_capability(
                &state.secret,
                actor,
                "message",
                p.scope,
                json!({"text": p.message}),
                Some(peer.outbound.capability_id),
            )?;
            let ack = send_envelope(&state.endpoint, peer.endpoint_addr, &envelope).await?;
            if !ack.ok {
                bail!(
                    "peer rejected message: {}",
                    ack.error.unwrap_or_else(|| "unknown error".to_owned())
                );
            }
            Ok(json!({"message_id": envelope.message_id, "acknowledged": true}))
        }
        "inbox.list" => {
            #[derive(Deserialize)]
            struct P {
                limit: Option<usize>,
            }
            let p: P = serde_json::from_value(request.params.clone()).unwrap_or(P { limit: None });
            Ok(serde_json::to_value(
                state.store.lock().await.inbox(p.limit.unwrap_or(20))?,
            )?)
        }
        "audit.tail" => {
            #[derive(Deserialize)]
            struct P {
                limit: Option<usize>,
            }
            let p: P = serde_json::from_value(request.params.clone()).unwrap_or(P { limit: None });
            Ok(serde_json::to_value(
                state.store.lock().await.audit_tail(p.limit.unwrap_or(20))?,
            )?)
        }
        "audit.verify" => {
            state.store.lock().await.verify_audit_chain()?;
            Ok(json!({
                "valid": true,
                "endpoint_id": state.endpoint.id().to_string(),
            }))
        }
        _ => bail!("unknown RPC method: {}", request.method),
    }
}

fn admin_required(method: &str) -> bool {
    matches!(
        method,
        "session.unlock"
            | "session.unlock-external"
            | "delegations.approve"
            | "delegations.revoke"
            | "invites.create"
            | "peers.join"
            | "peers.block"
            | "peers.unblock"
            | "peers.revoke"
            | "services.register"
    )
}

fn session_scope(method: &str) -> Option<SessionScope> {
    if matches!(
        method,
        "tasks.create" | "tasks.claim" | "tasks.submit" | "reviews.record" | "memory.propose"
    ) {
        Some(SessionScope::Routine)
    } else if matches!(
        method,
        "delegations.request" | "peer.send" | "services.call"
    ) {
        Some(SessionScope::External)
    } else {
        None
    }
}

fn approval_binding(method: &str, params: &Value) -> Result<String> {
    let digest = blake3::hash(&serde_json::to_vec(params)?);
    Ok(format!("{method}:{}", digest.to_hex()))
}

fn empty_object() -> Value {
    json!({})
}

fn approval_summary(method: &str, params: &Value) -> String {
    let text = |key: &str| short_text(params[key].as_str().unwrap_or("unspecified"));
    match method {
        "session.unlock" => "Unlock routine agent work".to_owned(),
        "session.unlock-external" => "Unlock external messages and service calls".to_owned(),
        "delegations.approve" => format!(
            "Approve request {} for operations [{}], {} minutes, and at most {} calls",
            text("request_id"),
            string_list(&params["operations"]),
            params["expires_minutes"].as_i64().unwrap_or_default(),
            params["max_calls"].as_u64().unwrap_or_default()
        ),
        "delegations.revoke" => format!("Revoke service grant {}", text("grant_id")),
        "services.register" => format!(
            "Register service {} with operations [{}]; network {}",
            text("name"),
            object_keys(&params["operations"]),
            if params["allow_network"].as_bool().unwrap_or(false) {
                "enabled"
            } else {
                "disabled"
            }
        ),
        "invites.create" => format!(
            "Create invite for {} with scopes [{}] for {} hours",
            text("invitee_label"),
            string_list(&params["scopes"]),
            params["expires_hours"].as_i64().unwrap_or_default()
        ),
        "peers.join" => "Join using the supplied private invitation".to_owned(),
        "peers.block" => format!("Block peer {}", text("endpoint_id")),
        "peers.unblock" => format!("Unblock peer {}", text("endpoint_id")),
        "peers.revoke" => format!("Revoke peer {}", text("endpoint_id")),
        _ => format!("Approve protected action {method}"),
    }
}

fn short_text(value: &str) -> String {
    value.chars().take(80).collect()
}

fn string_list(value: &Value) -> String {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .take(8)
        .map(short_text)
        .collect::<Vec<_>>()
        .join(", ")
}

fn object_keys(value: &Value) -> String {
    value
        .as_object()
        .into_iter()
        .flat_map(|object| object.keys())
        .take(8)
        .map(|key| short_text(key))
        .collect::<Vec<_>>()
        .join(", ")
}

fn classify_error(error: &anyhow::Error) -> &'static str {
    let text = error.to_string();
    if text.contains("permission denied")
        || text.contains("review")
        || text.contains("not ready")
        || text.contains("only the assigned")
        || text.contains("session is locked or expired")
    {
        "policy_denied"
    } else if text.contains("unknown RPC") {
        "method_not_found"
    } else {
        "invalid_request"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn administrator_binding_changes_with_exact_parameters() {
        let first = json!({
            "request_id": "request-a",
            "operations": ["inspect"],
            "expires_minutes": 15,
            "max_calls": 2,
        });
        let changed = json!({
            "request_id": "request-a",
            "operations": ["inspect"],
            "expires_minutes": 15,
            "max_calls": 3,
        });
        assert_eq!(
            approval_binding("delegations.approve", &first).unwrap(),
            approval_binding("delegations.approve", &first).unwrap()
        );
        assert_ne!(
            approval_binding("delegations.approve", &first).unwrap(),
            approval_binding("delegations.approve", &changed).unwrap()
        );
    }

    #[test]
    fn invitation_summary_does_not_include_the_bearer_value() {
        let params = json!({"token": "not-for-display"});
        let summary = approval_summary("peers.join", &params);
        assert!(!summary.contains("not-for-display"));
    }
}
