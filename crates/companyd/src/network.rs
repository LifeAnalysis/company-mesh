use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, endpoint::presets};
use serde::Deserialize;
use serde_json::{json, to_vec};
use tokio::{
    sync::{Mutex, Semaphore},
    task::JoinSet,
    time::timeout,
};
use tracing::{info, warn};

use crate::{
    delegation::ServiceDefinition,
    model::{ALPN, Ack, Envelope, MAX_ENVELOPE_BYTES},
    sandbox::{NoCredentialProvider, prepare_command},
    store::Store,
};

pub async fn build_endpoint(secret: SecretKey, use_relay: bool) -> Result<Endpoint> {
    let relay_mode = if use_relay {
        RelayMode::Default
    } else {
        RelayMode::Disabled
    };
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(relay_mode)
        .bind()
        .await
        .context("bind Iroh endpoint")?;
    Ok(endpoint)
}

pub async fn send_envelope(
    endpoint: &Endpoint,
    address: EndpointAddr,
    envelope: &Envelope,
) -> Result<Ack> {
    let bytes = to_vec(envelope)?;
    if bytes.len() > MAX_ENVELOPE_BYTES {
        bail!("envelope exceeds maximum size");
    }
    let connection = timeout(Duration::from_secs(30), endpoint.connect(address, ALPN))
        .await
        .context("Iroh connection timed out")?
        .context("connect to Iroh peer")?;
    let (mut send, mut receive) = timeout(Duration::from_secs(10), connection.open_bi())
        .await
        .context("opening Iroh stream timed out")?
        .context("open Iroh stream")?;
    timeout(Duration::from_secs(10), send.write_all(&bytes))
        .await
        .context("writing envelope timed out")?
        .context("write envelope")?;
    send.finish().context("finish envelope stream")?;
    let response = timeout(Duration::from_secs(30), receive.read_to_end(64 * 1024))
        .await
        .context("acknowledgement timed out")?
        .context("read acknowledgement")?;
    let ack: Ack = serde_json::from_slice(&response).context("parse acknowledgement")?;
    connection.close(0u32.into(), b"complete");
    Ok(ack)
}

pub async fn accept_loop(
    endpoint: Endpoint,
    store: Arc<Mutex<Store>>,
    notifications: bool,
) -> Result<()> {
    let mut connections = JoinSet::new();
    let connection_limit = Arc::new(Semaphore::new(64));
    while let Some(incoming) = endpoint.accept().await {
        let permit = connection_limit.clone().acquire_owned().await?;
        let store = store.clone();
        connections.spawn(async move {
            let _permit = permit;
            let connection = timeout(Duration::from_secs(30), incoming)
                .await
                .context("Iroh handshake timed out")?
                .context("accept Iroh connection")?;
            let remote_id = connection.remote_id();
            let (mut send, mut receive) = timeout(Duration::from_secs(10), connection.accept_bi())
                .await
                .context("waiting for Iroh stream timed out")?
                .context("accept Iroh stream")?;
            let bytes = timeout(
                Duration::from_secs(30),
                receive.read_to_end(MAX_ENVELOPE_BYTES),
            )
            .await
            .context("reading envelope timed out")?
            .context("read envelope")?;
            let parsed = serde_json::from_slice::<Envelope>(&bytes).context("parse envelope");
            let ack = match parsed {
                Ok(envelope) => {
                    let result = async {
                        envelope.verify(remote_id, Utc::now())?;
                        store.lock().await.record_nonce(
                            &envelope.sender_endpoint,
                            &envelope.nonce,
                            envelope.expires_at,
                        )?;
                        if envelope.kind == "enrollment_request" {
                            #[derive(Deserialize)]
                            struct Enrollment {
                                invite_token: String,
                                endpoint_addr: EndpointAddr,
                            }
                            let request: Enrollment =
                                serde_json::from_value(envelope.payload.clone())?;
                            store.lock().await.accept_enrollment(
                                &envelope.sender_endpoint,
                                request.endpoint_addr,
                                &request.invite_token,
                            )?;
                            Ok::<_, anyhow::Error>((None, None))
                        } else {
                            let payload_type = envelope.payload["type"].as_str();
                            if payload_type == Some("service_request") {
                                let token = envelope.payload["grant_token"]
                                    .as_str()
                                    .context("service request omitted grant")?;
                                let operation = envelope.payload["operation"]
                                    .as_str()
                                    .context("service request omitted operation")?;
                                let (definition, project, label) = {
                                    let store = store.lock().await;
                                    let peer = store.authorize_inbound(
                                        &envelope.sender_endpoint,
                                        envelope.capability_ref.as_deref(),
                                        "message",
                                        &envelope.scope,
                                    )?;
                                    let (definition, project) = store.authorize_service_call(
                                        &envelope.sender_endpoint,
                                        token,
                                        operation,
                                    )?;
                                    (definition, project, peer.label)
                                };
                                let output =
                                    execute_service(&definition, operation, &project).await?;
                                Ok((Some(label), Some(output)))
                            } else {
                                let store = store.lock().await;
                                let peer = store.authorize_inbound(
                                    &envelope.sender_endpoint,
                                    envelope.capability_ref.as_deref(),
                                    &envelope.kind,
                                    &envelope.scope,
                                )?;
                                let recorded_payload = if payload_type == Some("service_grant") {
                                    let token = envelope.payload["token"]
                                        .as_str()
                                        .context("service grant omitted token")?;
                                    let details = store
                                        .accept_service_grant(&envelope.sender_endpoint, token)?;
                                    json!({"type": "service_grant", "grant": details})
                                } else {
                                    envelope.payload.clone()
                                };
                                store.record_inbox(
                                    &envelope.sender_endpoint,
                                    &envelope.sender_agent,
                                    &envelope.message_id.to_string(),
                                    &envelope.kind,
                                    &envelope.scope,
                                    &recorded_payload,
                                )?;
                                Ok((Some(peer.label), None))
                            }
                        }
                    }
                    .await;
                    match result {
                        Ok((peer_label, response_result)) => {
                            if let Some(peer_label) = peer_label {
                                crate::notify::inbound_message(
                                    notifications,
                                    &peer_label,
                                    &envelope.scope,
                                )
                                .await?;
                            }
                            Ack {
                                ok: true,
                                message_id: envelope.message_id,
                                error: None,
                                result: response_result,
                            }
                        }
                        Err(error) => {
                            warn!(%remote_id, %error, "rejected peer envelope");
                            Ack {
                                ok: false,
                                message_id: envelope.message_id,
                                error: Some(error.to_string()),
                                result: None,
                            }
                        }
                    }
                }
                Err(error) => Ack {
                    ok: false,
                    message_id: uuid::Uuid::nil(),
                    error: Some(error.to_string()),
                    result: None,
                },
            };
            timeout(
                Duration::from_secs(10),
                send.write_all(&serde_json::to_vec(&ack)?),
            )
            .await
            .context("writing acknowledgement timed out")??;
            send.finish()?;
            let _ = tokio::time::timeout(Duration::from_secs(5), connection.closed()).await;
            Ok::<_, anyhow::Error>(())
        });

        while let Some(result) = connections.try_join_next() {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => warn!(%error, "peer connection failed"),
                Err(error) => warn!(%error, "peer connection task failed"),
            }
        }
    }
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result? {
            warn!(%error, "peer connection failed during shutdown");
        }
    }
    info!("Iroh accept loop stopped");
    Ok(())
}

async fn execute_service(
    definition: &ServiceDefinition,
    operation: &str,
    project: &str,
) -> Result<serde_json::Value> {
    let actual_hash = blake3::hash(&std::fs::read(&definition.executable)?)
        .to_hex()
        .to_string();
    if definition.executable_hash.is_empty() || actual_hash != definition.executable_hash {
        bail!("delegated service executable changed after registration");
    }
    let mut sandboxed = prepare_command(definition, operation, project, &NoCredentialProvider)?;
    let output = timeout(
        Duration::from_secs(definition.timeout_seconds),
        sandboxed.command.output(),
    )
    .await
    .context("delegated service timed out")??;
    let limit = definition.max_output_bytes;
    let stdout = String::from_utf8_lossy(&output.stdout[..output.stdout.len().min(limit)]);
    let stderr = String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(limit)]);
    Ok(serde_json::json!({
        "service": definition.name,
        "operation": operation,
        "project": project,
        "success": output.status.success(),
        "exit_code": output.status.code(),
        "stdout": stdout,
        "stderr": stderr,
        "truncated": output.stdout.len() > limit || output.stderr.len() > limit,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Envelope;

    #[tokio::test]
    async fn two_nodes_exchange_an_authenticated_envelope_and_reject_replay() {
        let dir = tempfile::tempdir().unwrap();
        let receiver_key = SecretKey::generate();
        let store = Arc::new(Mutex::new(
            Store::open(&dir.path().join("receiver.db"), receiver_key.clone()).unwrap(),
        ));
        let receiver = build_endpoint(receiver_key.clone(), false).await.unwrap();
        let accept_task = tokio::spawn(accept_loop(receiver.clone(), store.clone(), false));
        let sender_key = SecretKey::generate();
        let sender = build_endpoint(sender_key.clone(), false).await.unwrap();
        let now = Utc::now();
        let invite = crate::invite::SignedInvite::issue(
            &receiver_key,
            crate::invite::InviteClaims {
                protocol: crate::model::PROTOCOL.to_owned(),
                invite_id: uuid::Uuid::new_v4(),
                organization: "test".to_owned(),
                issuer_endpoint: receiver.id().to_string(),
                issuer_addr: receiver.addr(),
                issuer_label: "receiver".to_owned(),
                invitee_label: "sender".to_owned(),
                issued_at: now,
                expires_at: now + chrono::Duration::hours(1),
                joiner_to_inviter: crate::invite::CapabilityGrant::messages(
                    vec!["project:test".into()],
                    10,
                )
                .unwrap(),
                inviter_to_joiner: crate::invite::CapabilityGrant::messages(
                    vec!["project:test".into()],
                    10,
                )
                .unwrap(),
            },
        )
        .unwrap();
        let token = invite.encode().unwrap();
        store.lock().await.register_invite("owner", &token).unwrap();
        let enrollment = Envelope::new(
            &sender_key,
            "agent:sender",
            "enrollment_request",
            "company:peers",
            serde_json::json!({"invite_token": token, "endpoint_addr": sender.addr()}),
        )
        .unwrap();
        assert!(
            send_envelope(&sender, receiver.addr(), &enrollment)
                .await
                .unwrap()
                .ok
        );
        let envelope = Envelope::new_with_capability(
            &sender_key,
            "agent:sender",
            "message",
            "project:test",
            serde_json::json!({"text": "hello"}),
            Some(invite.claims.joiner_to_inviter.capability_id.clone()),
        )
        .unwrap();
        let first = send_envelope(&sender, receiver.addr(), &envelope)
            .await
            .unwrap();
        assert!(first.ok);
        let replay = send_envelope(&sender, receiver.addr(), &envelope)
            .await
            .unwrap();
        assert!(!replay.ok);
        assert!(replay.error.unwrap().contains("replayed"));
        assert_eq!(store.lock().await.inbox(10).unwrap().len(), 1);
        sender.close().await;
        receiver.close().await;
        accept_task.await.unwrap().unwrap();
    }
}
