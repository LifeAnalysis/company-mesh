use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use chrono::{DateTime, Utc};
use iroh::{EndpointAddr, SecretKey, Signature};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    delegation::{ServiceDefinition, ServiceGrantClaims, SignedServiceGrant},
    invite::{CapabilityGrant, SignedInvite},
    model::valid_scope,
};

pub struct Store {
    conn: Connection,
    secret: SecretKey,
}

pub struct MemoryProposal<'a> {
    pub scope: &'a str,
    pub kind: &'a str,
    pub content: &'a str,
    pub source_uri: &'a str,
    pub valid_from: Option<&'a str>,
    pub supersedes: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub endpoint_id: String,
    pub label: String,
    pub endpoint_addr: EndpointAddr,
    pub organization: String,
    pub status: String,
    pub inbound: CapabilityGrant,
    pub outbound: CapabilityGrant,
    pub enrolled_at: String,
}

impl Store {
    pub fn open(path: &Path, secret: SecretKey) -> Result<Self> {
        let conn =
            Connection::open(path).with_context(|| format!("open database {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL,
                scope TEXT NOT NULL,
                actor TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL UNIQUE,
                signature TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                project TEXT NOT NULL,
                state TEXT NOT NULL,
                depends_on TEXT NOT NULL,
                parallel_safe INTEGER NOT NULL,
                assigned_to TEXT,
                evidence TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS memories (
                memory_id TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                kind TEXT NOT NULL,
                content TEXT NOT NULL,
                source_uri TEXT NOT NULL,
                source_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                valid_from TEXT,
                supersedes TEXT,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS memories_scope_idx ON memories(scope, status);
            CREATE TABLE IF NOT EXISTS reviews (
                review_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                reviewer TEXT NOT NULL,
                verdict TEXT NOT NULL,
                artifact TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(task_id)
            );
            CREATE TABLE IF NOT EXISTS inbox (
                message_id TEXT PRIMARY KEY,
                sender_endpoint TEXT NOT NULL,
                sender_agent TEXT NOT NULL,
                kind TEXT NOT NULL,
                scope TEXT NOT NULL,
                payload TEXT NOT NULL,
                received_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS nonces (
                sender_endpoint TEXT NOT NULL,
                nonce TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                PRIMARY KEY(sender_endpoint, nonce)
            );
            CREATE TABLE IF NOT EXISTS invitations (
                invite_id TEXT PRIMARY KEY,
                token TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                used_by TEXT
            );
            CREATE TABLE IF NOT EXISTS peers (
                endpoint_id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                endpoint_addr TEXT NOT NULL,
                organization TEXT NOT NULL,
                status TEXT NOT NULL,
                inbound_capability TEXT NOT NULL,
                outbound_capability TEXT NOT NULL,
                enrolled_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS peer_rate_events (
                endpoint_id TEXT NOT NULL,
                received_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS peer_rate_idx ON peer_rate_events(endpoint_id, received_at);
            CREATE TABLE IF NOT EXISTS delegated_services (
                name TEXT PRIMARY KEY,
                definition TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS service_grants (
                grant_id TEXT PRIMARY KEY,
                direction TEXT NOT NULL,
                peer_endpoint TEXT NOT NULL,
                token TEXT NOT NULL,
                service TEXT NOT NULL,
                project TEXT NOT NULL,
                operations TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                max_calls INTEGER NOT NULL,
                calls_used INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            "#,
        )?;
        Ok(Self { conn, secret })
    }

    pub fn append_event(
        &self,
        kind: &str,
        scope: &str,
        actor: &str,
        payload: &Value,
    ) -> Result<String> {
        let event_id = Uuid::new_v4().to_string();
        let created_at = Utc::now().to_rfc3339();
        let previous_hash = self
            .conn
            .query_row(
                "SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_else(|| "0".repeat(64));
        let material = json!({
            "event_id": event_id,
            "kind": kind,
            "scope": scope,
            "actor": actor,
            "payload": payload,
            "created_at": created_at,
            "previous_hash": previous_hash,
        });
        let event_hash = blake3::hash(&serde_json::to_vec(&material)?)
            .to_hex()
            .to_string();
        let signature = STANDARD_NO_PAD.encode(self.secret.sign(event_hash.as_bytes()).to_bytes());
        self.conn.execute(
            "INSERT INTO events(event_id,kind,scope,actor,payload,created_at,previous_hash,event_hash,signature) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![event_id, kind, scope, actor, payload.to_string(), created_at, previous_hash, event_hash, signature],
        )?;
        Ok(event_id)
    }

    pub fn create_task(
        &self,
        actor: &str,
        task_id: &str,
        title: &str,
        project: &str,
        depends_on: &[String],
        parallel_safe: bool,
    ) -> Result<Value> {
        validate_identifier(task_id, "task_id")?;
        validate_identifier(project, "project")?;
        if title.trim().is_empty() || title.len() > 500 {
            bail!("title must contain 1 to 500 characters");
        }
        let existing: HashSet<String> = self
            .all_tasks()?
            .into_iter()
            .map(|task| task["task_id"].as_str().unwrap_or_default().to_owned())
            .collect();
        for dependency in depends_on {
            if dependency == task_id {
                bail!("task cannot depend on itself");
            }
            if !existing.contains(dependency) {
                bail!("unknown dependency: {dependency}");
            }
        }
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO tasks(task_id,title,project,state,depends_on,parallel_safe,created_at,updated_at) VALUES(?1,?2,?3,'pending',?4,?5,?6,?6)",
            params![task_id, title.trim(), project, serde_json::to_string(depends_on)?, parallel_safe, now],
        )?;
        let value = json!({
            "task_id": task_id, "title": title.trim(), "project": project,
            "state": "pending", "depends_on": depends_on, "parallel_safe": parallel_safe
        });
        self.append_event("task.created", &format!("project:{project}"), actor, &value)?;
        Ok(value)
    }

    pub fn ready_tasks(&self, project: Option<&str>) -> Result<Vec<Value>> {
        let tasks = self.all_tasks()?;
        let states: HashMap<String, String> = tasks
            .iter()
            .map(|task| {
                (
                    task["task_id"].as_str().unwrap_or_default().to_owned(),
                    task["state"].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        Ok(tasks
            .into_iter()
            .filter(|task| task["state"] == "pending")
            .filter(|task| project.is_none_or(|p| task["project"] == p))
            .filter(|task| {
                task["depends_on"].as_array().is_some_and(|deps| {
                    deps.iter().all(|dep| {
                        states
                            .get(dep.as_str().unwrap_or_default())
                            .is_some_and(|state| state == "complete")
                    })
                })
            })
            .collect())
    }

    pub fn claim_task(&self, actor: &str, task_id: &str) -> Result<Value> {
        let ready = self.ready_tasks(None)?;
        if !ready.iter().any(|task| task["task_id"] == task_id) {
            bail!("task is not ready");
        }
        let changed = self.conn.execute(
            "UPDATE tasks SET state='running', assigned_to=?1, updated_at=?2 WHERE task_id=?3 AND state='pending'",
            params![actor, Utc::now().to_rfc3339(), task_id],
        )?;
        if changed != 1 {
            bail!("task claim lost to another agent");
        }
        let result = json!({"task_id": task_id, "state": "running", "assigned_to": actor});
        self.append_event("task.claimed", &format!("task:{task_id}"), actor, &result)?;
        Ok(result)
    }

    pub fn submit_task(
        &self,
        actor: &str,
        task_id: &str,
        tests_passed: bool,
        review_id: &str,
        commit: &str,
    ) -> Result<Value> {
        if !tests_passed {
            bail!("deterministic test gate did not pass");
        }
        if review_id.trim().is_empty() || commit.trim().is_empty() {
            bail!("review ID and commit are required");
        }
        let assignee: Option<String> = self
            .conn
            .query_row(
                "SELECT assigned_to FROM tasks WHERE task_id=?1 AND state='running'",
                [task_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        if assignee.as_deref() != Some(actor) {
            bail!("only the assigned agent can submit this task");
        }
        let review: Option<(String, String, String)> = self
            .conn
            .query_row(
                "SELECT reviewer,verdict,artifact FROM reviews WHERE review_id=?1 AND task_id=?2",
                params![review_id, task_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let (reviewer, verdict, review_artifact) =
            review.context("approved review record not found")?;
        if reviewer == actor || verdict != "approved" {
            bail!("completion requires an approved review from an independent agent");
        }
        let evidence = json!({
            "tests_passed": true,
            "reviewer": reviewer,
            "review_artifact": review_artifact,
            "review_id": review_id,
            "commit": commit
        });
        self.conn.execute(
            "UPDATE tasks SET state='complete', evidence=?1, updated_at=?2 WHERE task_id=?3",
            params![evidence.to_string(), Utc::now().to_rfc3339(), task_id],
        )?;
        self.append_event(
            "task.completed",
            &format!("task:{task_id}"),
            actor,
            &evidence,
        )?;
        Ok(json!({"task_id": task_id, "state": "complete", "evidence": evidence}))
    }

    pub fn record_review(
        &self,
        actor: &str,
        task_id: &str,
        approved: bool,
        artifact: &str,
    ) -> Result<Value> {
        if artifact.trim().is_empty() {
            bail!("review artifact is required");
        }
        let assignee: Option<String> = self
            .conn
            .query_row(
                "SELECT assigned_to FROM tasks WHERE task_id=?1 AND state='running'",
                [task_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        let assignee = assignee.context("task is not running")?;
        if assignee == actor {
            bail!("assigned agent cannot review its own task");
        }
        let review_id = Uuid::new_v4().to_string();
        let verdict = if approved {
            "approved"
        } else {
            "changes_requested"
        };
        self.conn.execute(
            "INSERT INTO reviews(review_id,task_id,reviewer,verdict,artifact,created_at) VALUES(?1,?2,?3,?4,?5,?6)",
            params![review_id, task_id, actor, verdict, artifact.trim(), Utc::now().to_rfc3339()],
        )?;
        let value = json!({"review_id": review_id, "task_id": task_id, "reviewer": actor, "verdict": verdict, "artifact": artifact.trim()});
        self.append_event("review.recorded", &format!("task:{task_id}"), actor, &value)?;
        Ok(value)
    }

    pub fn propose_memory(&self, actor: &str, proposal: MemoryProposal<'_>) -> Result<Value> {
        let MemoryProposal {
            scope,
            kind,
            content,
            source_uri,
            valid_from,
            supersedes,
        } = proposal;
        if !valid_scope(scope) {
            bail!("invalid memory scope");
        }
        if !matches!(
            kind,
            "observation" | "decision" | "fact" | "handoff" | "incident"
        ) {
            bail!("invalid memory kind");
        }
        if content.trim().is_empty() || content.len() > 50_000 {
            bail!("memory content must contain 1 to 50000 characters");
        }
        if source_uri.trim().is_empty() || source_uri.len() > 2048 {
            bail!("source_uri is required");
        }
        if let Some(value) = valid_from {
            DateTime::parse_from_rfc3339(value).context("valid_from must be RFC3339")?;
        }
        if let Some(value) = supersedes {
            Uuid::parse_str(value).context("supersedes must be a UUID")?;
            let exists: bool = self.conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM memories WHERE memory_id=?1)",
                [value],
                |row| row.get(0),
            )?;
            if !exists {
                bail!("superseded memory does not exist");
            }
        }
        let memory_id = Uuid::new_v4().to_string();
        let source_hash = blake3::hash(format!("{source_uri}\0{}", content.trim()).as_bytes())
            .to_hex()
            .to_string();
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO memories(memory_id,scope,kind,content,source_uri,source_hash,status,valid_from,supersedes,created_by,created_at) VALUES(?1,?2,?3,?4,?5,?6,'proposed',?7,?8,?9,?10)",
            params![memory_id, scope, kind, content.trim(), source_uri, source_hash, valid_from, supersedes, actor, now],
        )?;
        let value = json!({
            "memory_id": memory_id, "scope": scope, "kind": kind, "content": content.trim(),
            "source_uri": source_uri, "source_hash": source_hash, "status": "proposed",
            "valid_from": valid_from, "supersedes": supersedes, "created_by": actor
        });
        self.append_event("memory.proposed", scope, actor, &value)?;
        Ok(value)
    }

    pub fn search_memory(&self, scope: &str, query: &str, limit: usize) -> Result<Vec<Value>> {
        if !valid_scope(scope) {
            bail!("invalid memory scope");
        }
        if query.trim().is_empty() {
            bail!("query is required");
        }
        let mut statement = self.conn.prepare(
            "SELECT memory_id,scope,kind,content,source_uri,source_hash,status,valid_from,supersedes,created_by,created_at FROM memories WHERE scope=?1 AND content LIKE ?2 ORDER BY created_at DESC LIMIT ?3"
        )?;
        let pattern = format!("%{}%", query.trim());
        let rows = statement.query_map(params![scope, pattern, limit.min(50) as i64], |row| {
            Ok(json!({
                "memory_id": row.get::<_, String>(0)?, "scope": row.get::<_, String>(1)?,
                "kind": row.get::<_, String>(2)?, "content": row.get::<_, String>(3)?,
                "source_uri": row.get::<_, String>(4)?, "source_hash": row.get::<_, String>(5)?,
                "status": row.get::<_, String>(6)?, "valid_from": row.get::<_, Option<String>>(7)?,
                "supersedes": row.get::<_, Option<String>>(8)?, "created_by": row.get::<_, String>(9)?,
                "created_at": row.get::<_, String>(10)?
            }))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn record_nonce(&self, sender: &str, nonce: &str, expires_at: DateTime<Utc>) -> Result<()> {
        self.conn.execute(
            "DELETE FROM nonces WHERE expires_at < ?1",
            [Utc::now().to_rfc3339()],
        )?;
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO nonces(sender_endpoint,nonce,expires_at) VALUES(?1,?2,?3)",
            params![sender, nonce, expires_at.to_rfc3339()],
        )?;
        if inserted != 1 {
            bail!("replayed envelope");
        }
        Ok(())
    }

    pub fn register_invite(&self, actor: &str, token: &str) -> Result<Value> {
        let invite = SignedInvite::decode(token)?;
        if invite.claims.issuer_endpoint != self.secret.public().to_string() {
            bail!("cannot register an invite signed by another node");
        }
        self.conn.execute(
            "INSERT INTO invitations(invite_id,token,expires_at,status,created_at) VALUES(?1,?2,?3,'issued',?4)",
            params![
                invite.claims.invite_id.to_string(),
                token,
                invite.claims.expires_at.to_rfc3339(),
                Utc::now().to_rfc3339()
            ],
        )?;
        let value = json!({
            "invite_id": invite.claims.invite_id,
            "invitee_label": invite.claims.invitee_label,
            "expires_at": invite.claims.expires_at,
            "scopes": invite.claims.joiner_to_inviter.scope_prefixes,
        });
        self.append_event("invite.created", "company:peers", actor, &value)?;
        Ok(value)
    }

    pub fn accept_enrollment(
        &self,
        remote_endpoint: &str,
        remote_addr: EndpointAddr,
        token: &str,
    ) -> Result<PeerRecord> {
        let invite = SignedInvite::decode(token)?;
        if invite.claims.issuer_endpoint != self.secret.public().to_string() {
            bail!("invite was not issued by this node");
        }
        let status: Option<String> = self
            .conn
            .query_row(
                "SELECT status FROM invitations WHERE invite_id=?1 AND token=?2 AND expires_at>?3",
                params![
                    invite.claims.invite_id.to_string(),
                    token,
                    Utc::now().to_rfc3339()
                ],
                |row| row.get(0),
            )
            .optional()?;
        if status.as_deref() != Some("issued") {
            bail!("invite is unknown, expired, revoked, or already used");
        }
        if remote_addr.id.to_string() != remote_endpoint {
            bail!("enrollment address does not match the authenticated peer");
        }
        let peer = PeerRecord {
            endpoint_id: remote_endpoint.to_owned(),
            label: invite.claims.invitee_label.clone(),
            endpoint_addr: remote_addr,
            organization: invite.claims.organization.clone(),
            status: "active".to_owned(),
            inbound: invite.claims.joiner_to_inviter.clone(),
            outbound: invite.claims.inviter_to_joiner.clone(),
            enrolled_at: Utc::now().to_rfc3339(),
        };
        self.upsert_peer(&peer)?;
        self.conn.execute(
            "UPDATE invitations SET status='used', used_by=?1 WHERE invite_id=?2 AND status='issued'",
            params![remote_endpoint, invite.claims.invite_id.to_string()],
        )?;
        self.append_event(
            "peer.enrolled",
            "company:peers",
            remote_endpoint,
            &serde_json::to_value(&peer)?,
        )?;
        Ok(peer)
    }

    pub fn trust_inviter(&self, actor: &str, invite: &SignedInvite) -> Result<PeerRecord> {
        invite.verify(Utc::now())?;
        let peer = PeerRecord {
            endpoint_id: invite.claims.issuer_endpoint.clone(),
            label: invite.claims.issuer_label.clone(),
            endpoint_addr: invite.claims.issuer_addr.clone(),
            organization: invite.claims.organization.clone(),
            status: "active".to_owned(),
            inbound: invite.claims.inviter_to_joiner.clone(),
            outbound: invite.claims.joiner_to_inviter.clone(),
            enrolled_at: Utc::now().to_rfc3339(),
        };
        self.upsert_peer(&peer)?;
        self.append_event(
            "peer.joined",
            "company:peers",
            actor,
            &serde_json::to_value(&peer)?,
        )?;
        Ok(peer)
    }

    fn upsert_peer(&self, peer: &PeerRecord) -> Result<()> {
        self.conn.execute(
            "INSERT INTO peers(endpoint_id,label,endpoint_addr,organization,status,inbound_capability,outbound_capability,enrolled_at,updated_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)
             ON CONFLICT(endpoint_id) DO UPDATE SET label=excluded.label, endpoint_addr=excluded.endpoint_addr,
             organization=excluded.organization, status=excluded.status,
             inbound_capability=excluded.inbound_capability, outbound_capability=excluded.outbound_capability,
             updated_at=excluded.updated_at",
            params![
                peer.endpoint_id,
                peer.label,
                serde_json::to_string(&peer.endpoint_addr)?,
                peer.organization,
                peer.status,
                serde_json::to_string(&peer.inbound)?,
                serde_json::to_string(&peer.outbound)?,
                peer.enrolled_at,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn authorize_inbound(
        &self,
        endpoint_id: &str,
        capability_id: Option<&str>,
        kind: &str,
        scope: &str,
    ) -> Result<PeerRecord> {
        let peer = self.peer(endpoint_id)?.context("peer is not enrolled")?;
        if peer.status != "active" {
            bail!("peer is blocked or revoked");
        }
        let capability_id = capability_id.context("peer capability is required")?;
        if !peer.inbound.allows(capability_id, kind, scope) {
            bail!("peer capability does not allow this message kind or scope");
        }
        let cutoff = (Utc::now() - chrono::Duration::minutes(1)).to_rfc3339();
        self.conn.execute(
            "DELETE FROM peer_rate_events WHERE received_at<?1",
            [&cutoff],
        )?;
        let count: u32 = self.conn.query_row(
            "SELECT COUNT(*) FROM peer_rate_events WHERE endpoint_id=?1 AND received_at>=?2",
            params![endpoint_id, cutoff],
            |row| row.get(0),
        )?;
        if count >= peer.inbound.max_messages_per_minute {
            bail!("peer message rate limit exceeded");
        }
        self.conn.execute(
            "INSERT INTO peer_rate_events(endpoint_id,received_at) VALUES(?1,?2)",
            params![endpoint_id, Utc::now().to_rfc3339()],
        )?;
        Ok(peer)
    }

    pub fn authorize_outbound(
        &self,
        endpoint_id: &str,
        kind: &str,
        scope: &str,
    ) -> Result<PeerRecord> {
        let peer = self.peer(endpoint_id)?.context("peer is not enrolled")?;
        if peer.status != "active" {
            bail!("peer is blocked or revoked");
        }
        if !peer
            .outbound
            .allows(&peer.outbound.capability_id, kind, scope)
        {
            bail!("outbound capability does not allow this message kind or scope");
        }
        Ok(peer)
    }

    pub fn peer(&self, endpoint_id: &str) -> Result<Option<PeerRecord>> {
        self.conn
            .query_row(
                "SELECT endpoint_id,label,endpoint_addr,organization,status,inbound_capability,outbound_capability,enrolled_at FROM peers WHERE endpoint_id=?1",
                [endpoint_id],
                |row| {
                    let endpoint_addr: String = row.get(2)?;
                    let inbound: String = row.get(5)?;
                    let outbound: String = row.get(6)?;
                    Ok((
                        row.get::<_, String>(0)?, row.get::<_, String>(1)?, endpoint_addr,
                        row.get::<_, String>(3)?, row.get::<_, String>(4)?, inbound, outbound,
                        row.get::<_, String>(7)?,
                    ))
                },
            )
            .optional()?
            .map(|row| {
                Ok(PeerRecord {
                    endpoint_id: row.0,
                    label: row.1,
                    endpoint_addr: serde_json::from_str(&row.2)?,
                    organization: row.3,
                    status: row.4,
                    inbound: serde_json::from_str(&row.5)?,
                    outbound: serde_json::from_str(&row.6)?,
                    enrolled_at: row.7,
                })
            })
            .transpose()
    }

    pub fn list_peers(&self) -> Result<Vec<PeerRecord>> {
        let mut statement = self
            .conn
            .prepare("SELECT endpoint_id FROM peers ORDER BY label")?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ids.iter()
            .map(|id| self.peer(id)?.context("peer disappeared"))
            .collect()
    }

    pub fn set_peer_status(&self, actor: &str, endpoint_id: &str, status: &str) -> Result<Value> {
        if !matches!(status, "active" | "blocked" | "revoked") {
            bail!("invalid peer status");
        }
        let changed = self.conn.execute(
            "UPDATE peers SET status=?1,updated_at=?2 WHERE endpoint_id=?3",
            params![status, Utc::now().to_rfc3339(), endpoint_id],
        )?;
        if changed != 1 {
            bail!("peer does not exist");
        }
        let value = json!({"endpoint_id": endpoint_id, "status": status});
        self.append_event("peer.status_changed", "company:peers", actor, &value)?;
        Ok(value)
    }

    pub fn register_service(&self, actor: &str, definition: &ServiceDefinition) -> Result<Value> {
        if definition.name.is_empty()
            || !std::path::Path::new(&definition.executable).is_absolute()
            || !std::path::Path::new(&definition.executable).is_file()
            || definition.operations.is_empty()
            || !(1..=900).contains(&definition.timeout_seconds)
            || !(1024..=1_048_576).contains(&definition.max_output_bytes)
        {
            bail!("invalid delegated service definition");
        }
        if definition.operations.iter().any(|(name, args)| {
            name.is_empty()
                || args.is_empty()
                || args
                    .iter()
                    .any(|arg| arg.contains('{') && arg != "{project}")
        }) {
            bail!("operation arguments may contain only the exact {{project}} placeholder");
        }
        let mut stored = definition.clone();
        stored.executable_hash = blake3::hash(&std::fs::read(&stored.executable)?)
            .to_hex()
            .to_string();
        self.conn.execute(
            "INSERT INTO delegated_services(name,definition,updated_at) VALUES(?1,?2,?3)
             ON CONFLICT(name) DO UPDATE SET definition=excluded.definition,updated_at=excluded.updated_at",
            params![stored.name, serde_json::to_string(&stored)?, Utc::now().to_rfc3339()],
        )?;
        let value = serde_json::to_value(&stored)?;
        self.append_event("service.registered", "company:services", actor, &value)?;
        Ok(value)
    }

    pub fn issue_service_grant(
        &self,
        actor: &str,
        request_message_id: &str,
        operations: &[String],
        expires_minutes: i64,
        max_calls: u32,
    ) -> Result<(PeerRecord, String, Value)> {
        if !(1..=1_440).contains(&expires_minutes) || !(1..=100).contains(&max_calls) {
            bail!("grant expiry or call limit is outside the allowed range");
        }
        let (sender_endpoint, scope, payload): (String, String, String) = self.conn.query_row(
            "SELECT sender_endpoint,scope,payload FROM inbox WHERE message_id=?1",
            [request_message_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let payload: Value = serde_json::from_str(&payload)?;
        if payload["type"] != "delegation_request" {
            bail!("message is not a delegation request");
        }
        let service = payload["service"]
            .as_str()
            .context("request omitted service")?;
        let project = payload["project"]
            .as_str()
            .context("request omitted project")?;
        let requested: Vec<String> = serde_json::from_value(payload["operations"].clone())?;
        if operations.is_empty() || operations.iter().any(|op| !requested.contains(op)) {
            bail!("approved operations must be a non-empty subset of the request");
        }
        let definition = self
            .service(service)?
            .context("requested service is not registered")?;
        if operations
            .iter()
            .any(|op| !definition.operations.contains_key(op))
        {
            bail!("an approved operation is not registered");
        }
        if scope != format!("project:{project}") {
            bail!("delegation project does not match its message scope");
        }
        let peer = self
            .peer(&sender_endpoint)?
            .context("requesting peer is not enrolled")?;
        let now = Utc::now();
        let grant = SignedServiceGrant::issue(
            &self.secret,
            ServiceGrantClaims {
                grant_id: Uuid::new_v4(),
                issuer_endpoint: self.secret.public().to_string(),
                grantee_endpoint: sender_endpoint.clone(),
                service: service.to_owned(),
                project: project.to_owned(),
                operations: operations.to_vec(),
                issued_at: now,
                expires_at: now + chrono::Duration::minutes(expires_minutes),
                max_calls,
            },
        )?;
        let token = grant.encode()?;
        self.insert_service_grant("issued", &sender_endpoint, &token, &grant)?;
        let details = json!({
            "grant_id": grant.claims.grant_id,
            "service": service,
            "project": project,
            "operations": operations,
            "expires_at": grant.claims.expires_at,
            "max_calls": max_calls,
        });
        self.append_event("service.grant.issued", &scope, actor, &details)?;
        Ok((peer, token, details))
    }

    pub fn accept_service_grant(&self, remote_endpoint: &str, token: &str) -> Result<Value> {
        let grant = SignedServiceGrant::decode(token)?;
        if grant.claims.issuer_endpoint != remote_endpoint
            || grant.claims.grantee_endpoint != self.secret.public().to_string()
        {
            bail!("service grant endpoints do not match this connection");
        }
        self.insert_service_grant("received", remote_endpoint, token, &grant)?;
        Ok(json!({
            "grant_id": grant.claims.grant_id,
            "service": grant.claims.service,
            "project": grant.claims.project,
            "operations": grant.claims.operations,
            "expires_at": grant.claims.expires_at,
            "max_calls": grant.claims.max_calls,
        }))
    }

    fn insert_service_grant(
        &self,
        direction: &str,
        peer_endpoint: &str,
        token: &str,
        grant: &SignedServiceGrant,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO service_grants(grant_id,direction,peer_endpoint,token,service,project,operations,expires_at,max_calls,calls_used,status,created_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,0,'active',?10)",
            params![grant.claims.grant_id.to_string(), direction, peer_endpoint, token,
                grant.claims.service, grant.claims.project, serde_json::to_string(&grant.claims.operations)?,
                grant.claims.expires_at.to_rfc3339(), grant.claims.max_calls, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn received_service_grants(&self) -> Result<Vec<Value>> {
        let mut statement = self.conn.prepare(
            "SELECT grant_id,peer_endpoint,service,project,operations,expires_at,max_calls,calls_used,status
             FROM service_grants WHERE direction='received' ORDER BY created_at DESC",
        )?;
        Ok(statement.query_map([], |row| {
            let operations: String = row.get(4)?;
            Ok(json!({"grant_id": row.get::<_, String>(0)?, "peer_endpoint": row.get::<_, String>(1)?,
                "service": row.get::<_, String>(2)?, "project": row.get::<_, String>(3)?,
                "operations": serde_json::from_str::<Value>(&operations).unwrap_or(Value::Null),
                "expires_at": row.get::<_, String>(5)?, "max_calls": row.get::<_, u32>(6)?,
                "calls_used": row.get::<_, u32>(7)?, "status": row.get::<_, String>(8)?}))
        })?.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn revoke_service_grant(&self, actor: &str, grant_id: &str) -> Result<Value> {
        let changed = self.conn.execute(
            "UPDATE service_grants SET status='revoked' WHERE grant_id=?1 AND direction='issued' AND status='active'",
            [grant_id],
        )?;
        if changed != 1 {
            bail!("issued service grant is unknown or already inactive");
        }
        let value = json!({"grant_id": grant_id, "status": "revoked"});
        self.append_event("service.grant.revoked", "company:services", actor, &value)?;
        Ok(value)
    }

    pub fn received_grant_token(&self, grant_id: &str) -> Result<String> {
        self.conn.query_row(
            "SELECT token FROM service_grants WHERE grant_id=?1 AND direction='received' AND status='active' AND expires_at>?2",
            params![grant_id, Utc::now().to_rfc3339()], |row| row.get(0),
        ).optional()?.context("service grant is unknown, inactive, or expired")
    }

    pub fn authorize_service_call(
        &self,
        remote_endpoint: &str,
        token: &str,
        operation: &str,
    ) -> Result<(ServiceDefinition, String)> {
        let grant = SignedServiceGrant::decode(token)?;
        if grant.claims.issuer_endpoint != self.secret.public().to_string()
            || grant.claims.grantee_endpoint != remote_endpoint
            || !grant
                .claims
                .operations
                .iter()
                .any(|value| value == operation)
        {
            bail!("service grant does not authorize this caller or operation");
        }
        let (calls, max_calls, status): (u32, u32, String) = self.conn.query_row(
            "SELECT calls_used,max_calls,status FROM service_grants WHERE grant_id=?1 AND direction='issued' AND expires_at>?2",
            params![grant.claims.grant_id.to_string(), Utc::now().to_rfc3339()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if status != "active" || calls >= max_calls {
            bail!("service grant is inactive or exhausted");
        }
        self.conn.execute(
            "UPDATE service_grants SET calls_used=calls_used+1 WHERE grant_id=?1",
            [grant.claims.grant_id.to_string()],
        )?;
        Ok((
            self.service(&grant.claims.service)?
                .context("service is no longer registered")?,
            grant.claims.project,
        ))
    }

    fn service(&self, name: &str) -> Result<Option<ServiceDefinition>> {
        self.conn
            .query_row(
                "SELECT definition FROM delegated_services WHERE name=?1",
                [name],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|value| serde_json::from_str(&value).map_err(Into::into))
            .transpose()
    }

    pub fn record_inbox(
        &self,
        sender_endpoint: &str,
        sender_agent: &str,
        message_id: &str,
        kind: &str,
        scope: &str,
        payload: &Value,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO inbox(message_id,sender_endpoint,sender_agent,kind,scope,payload,received_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![message_id, sender_endpoint, sender_agent, kind, scope, payload.to_string(), Utc::now().to_rfc3339()],
        )?;
        self.append_event("peer.received", scope, sender_agent, payload)?;
        Ok(())
    }

    pub fn inbox(&self, limit: usize) -> Result<Vec<Value>> {
        let mut statement = self.conn.prepare(
            "SELECT inbox.message_id,inbox.sender_endpoint,inbox.sender_agent,inbox.kind,inbox.scope,
                    inbox.payload,inbox.received_at,peers.endpoint_addr
             FROM inbox LEFT JOIN peers ON peers.endpoint_id=inbox.sender_endpoint
             ORDER BY inbox.received_at DESC LIMIT ?1"
        )?;
        let rows = statement.query_map([limit.min(100) as i64], |row| {
            let payload: String = row.get(5)?;
            let sender_addr: Option<String> = row.get(7)?;
            Ok(json!({
                "message_id": row.get::<_, String>(0)?, "sender_endpoint": row.get::<_, String>(1)?,
                "sender_agent": row.get::<_, String>(2)?, "kind": row.get::<_, String>(3)?,
                "scope": row.get::<_, String>(4)?, "payload": serde_json::from_str::<Value>(&payload).unwrap_or(Value::Null),
                "received_at": row.get::<_, String>(6)?,
                "sender_addr": sender_addr.and_then(|value| serde_json::from_str::<Value>(&value).ok())
            }))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn audit_tail(&self, limit: usize) -> Result<Vec<Value>> {
        let mut statement = self.conn.prepare(
            "SELECT seq,event_id,kind,scope,actor,payload,created_at,previous_hash,event_hash,signature FROM events ORDER BY seq DESC LIMIT ?1"
        )?;
        let rows = statement.query_map([limit.min(100) as i64], |row| {
            let payload: String = row.get(5)?;
            Ok(json!({
                "seq": row.get::<_, i64>(0)?, "event_id": row.get::<_, String>(1)?,
                "kind": row.get::<_, String>(2)?, "scope": row.get::<_, String>(3)?,
                "actor": row.get::<_, String>(4)?, "payload": serde_json::from_str::<Value>(&payload).unwrap_or(Value::Null),
                "created_at": row.get::<_, String>(6)?, "previous_hash": row.get::<_, String>(7)?,
                "event_hash": row.get::<_, String>(8)?, "signature": row.get::<_, String>(9)?
            }))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn verify_audit_chain(&self) -> Result<()> {
        let mut statement = self.conn.prepare(
            "SELECT event_id,kind,scope,actor,payload,created_at,previous_hash,event_hash,signature FROM events ORDER BY seq ASC"
        )?;
        let mut rows = statement.query([])?;
        let mut expected_previous = "0".repeat(64);
        while let Some(row) = rows.next()? {
            let event_id: String = row.get(0)?;
            let kind: String = row.get(1)?;
            let scope: String = row.get(2)?;
            let actor: String = row.get(3)?;
            let payload_text: String = row.get(4)?;
            let created_at: String = row.get(5)?;
            let previous_hash: String = row.get(6)?;
            let event_hash: String = row.get(7)?;
            let signature_text: String = row.get(8)?;
            if previous_hash != expected_previous {
                bail!("audit chain previous hash mismatch");
            }
            let payload: Value = serde_json::from_str(&payload_text)?;
            let material = json!({
                "event_id": event_id, "kind": kind, "scope": scope, "actor": actor,
                "payload": payload, "created_at": created_at, "previous_hash": previous_hash,
            });
            let actual_hash = blake3::hash(&serde_json::to_vec(&material)?)
                .to_hex()
                .to_string();
            if actual_hash != event_hash {
                bail!("audit event hash mismatch");
            }
            let signature = STANDARD_NO_PAD.decode(signature_text)?;
            let signature: [u8; Signature::LENGTH] = signature
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid audit signature length"))?;
            self.secret
                .public()
                .verify(event_hash.as_bytes(), &Signature::from_bytes(&signature))
                .map_err(|_| anyhow::anyhow!("invalid audit signature"))?;
            expected_previous = event_hash;
        }
        Ok(())
    }

    fn all_tasks(&self) -> Result<Vec<Value>> {
        let mut statement = self.conn.prepare(
            "SELECT task_id,title,project,state,depends_on,parallel_safe,assigned_to,evidence,created_at,updated_at FROM tasks ORDER BY task_id"
        )?;
        let rows = statement.query_map([], |row| {
            let dependencies: String = row.get(4)?;
            let evidence: Option<String> = row.get(7)?;
            Ok(json!({
                "task_id": row.get::<_, String>(0)?, "title": row.get::<_, String>(1)?,
                "project": row.get::<_, String>(2)?, "state": row.get::<_, String>(3)?,
                "depends_on": serde_json::from_str::<Value>(&dependencies).unwrap_or(json!([])),
                "parallel_safe": row.get::<_, bool>(5)?, "assigned_to": row.get::<_, Option<String>>(6)?,
                "evidence": evidence.and_then(|value| serde_json::from_str::<Value>(&value).ok()),
                "created_at": row.get::<_, String>(8)?, "updated_at": row.get::<_, String>(9)?
            }))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }
}

fn validate_identifier(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 80
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        bail!("{field} must contain only letters, numbers, dot, underscore, or dash");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependencies_and_independent_review_are_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("state.db"), SecretKey::generate()).unwrap();
        store
            .create_task("owner", "T1", "first", "mesh", &[], false)
            .unwrap();
        store
            .create_task("owner", "T2", "second", "mesh", &["T1".into()], true)
            .unwrap();
        assert_eq!(store.ready_tasks(None).unwrap().len(), 1);
        store.claim_task("builder", "T1").unwrap();
        assert!(
            store
                .record_review("builder", "T1", true, "review:a")
                .is_err()
        );
        let review = store
            .record_review("reviewer", "T1", true, "review:a")
            .unwrap();
        store
            .submit_task(
                "builder",
                "T1",
                true,
                review["review_id"].as_str().unwrap(),
                "abc",
            )
            .unwrap();
        assert_eq!(store.ready_tasks(None).unwrap()[0]["task_id"], "T2");
        store.verify_audit_chain().unwrap();
    }

    #[test]
    fn memory_requires_provenance() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("state.db"), SecretKey::generate()).unwrap();
        assert!(
            store
                .propose_memory(
                    "agent",
                    MemoryProposal {
                        scope: "project:mesh",
                        kind: "decision",
                        content: "Use Iroh",
                        source_uri: "",
                        valid_from: None,
                        supersedes: None,
                    }
                )
                .is_err()
        );
        store
            .propose_memory(
                "agent",
                MemoryProposal {
                    scope: "project:mesh",
                    kind: "decision",
                    content: "Use Iroh",
                    source_uri: "git:abc",
                    valid_from: None,
                    supersedes: None,
                },
            )
            .unwrap();
        assert_eq!(
            store
                .search_memory("project:mesh", "Iroh", 10)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn nonce_is_single_use() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("state.db"), SecretKey::generate()).unwrap();
        let expiry = Utc::now() + chrono::Duration::minutes(1);
        store
            .record_nonce("peer", "nonce-1234567890123456", expiry)
            .unwrap();
        assert!(
            store
                .record_nonce("peer", "nonce-1234567890123456", expiry)
                .is_err()
        );
    }

    #[test]
    fn peer_capabilities_rate_limits_and_revocation_are_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let owner = SecretKey::generate();
        let peer_key = SecretKey::generate();
        let store = Store::open(&dir.path().join("state.db"), owner.clone()).unwrap();
        let now = Utc::now();
        let invite = SignedInvite::issue(
            &owner,
            crate::invite::InviteClaims {
                protocol: crate::model::PROTOCOL.to_owned(),
                invite_id: Uuid::new_v4(),
                organization: "acme".to_owned(),
                issuer_endpoint: owner.public().to_string(),
                issuer_addr: EndpointAddr::new(owner.public()),
                issuer_label: "owner".to_owned(),
                invitee_label: "peer".to_owned(),
                issued_at: now,
                expires_at: now + chrono::Duration::hours(1),
                joiner_to_inviter: CapabilityGrant::messages(vec!["project:mesh".into()], 1)
                    .unwrap(),
                inviter_to_joiner: CapabilityGrant::messages(vec!["project:mesh".into()], 1)
                    .unwrap(),
            },
        )
        .unwrap();
        let token = invite.encode().unwrap();
        store.register_invite("owner", &token).unwrap();
        store
            .accept_enrollment(
                &peer_key.public().to_string(),
                EndpointAddr::new(peer_key.public()),
                &token,
            )
            .unwrap();
        assert!(
            store
                .authorize_inbound(
                    &peer_key.public().to_string(),
                    Some(&invite.claims.joiner_to_inviter.capability_id),
                    "message",
                    "project:mesh",
                )
                .is_ok()
        );
        assert!(
            store
                .authorize_inbound(
                    &peer_key.public().to_string(),
                    Some(&invite.claims.joiner_to_inviter.capability_id),
                    "message",
                    "project:mesh",
                )
                .is_err()
        );
        store
            .set_peer_status("owner", &peer_key.public().to_string(), "revoked")
            .unwrap();
        assert!(
            store
                .authorize_outbound(&peer_key.public().to_string(), "message", "project:mesh")
                .is_err()
        );
    }
}
