use std::{collections::BTreeSet, fs::OpenOptions, io::Write, path::Path};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub version: u32,
    pub organization: String,
    pub node_name: String,
    pub agent_id: String,
    pub permission_profile: PermissionProfile,
    pub enabled_actions: BTreeSet<String>,
    pub notifications: bool,
    pub automatic_loop: bool,
    pub max_loop_iterations: u8,
    #[serde(default = "default_session_minutes")]
    pub session_minutes: u16,
    #[serde(default)]
    pub allow_agent_override: bool,
    #[serde(default)]
    pub workload_identity: Option<WorkloadIdentityConfig>,
}

/// Configuration needed to bind the configured agent to a workload identity.
///
/// `spiffe_id` is optional until a SPIRE Workload API client is installed. The daemon
/// exposes these values as identity metadata; it does not yet treat them as an
/// authenticated claim.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkloadIdentityConfig {
    pub workload_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spire_socket_path: Option<String>,
}

impl WorkloadIdentityConfig {
    pub fn new(
        workload_id: String,
        spiffe_id: Option<String>,
        spire_socket_path: Option<String>,
    ) -> Result<Self> {
        if workload_id.trim().is_empty() || workload_id.len() > 255 {
            bail!("workload ID must contain 1 to 255 characters");
        }
        if let Some(id) = spiffe_id.as_deref() {
            validate_spiffe_id(id)?;
        }
        if spire_socket_path
            .as_deref()
            .is_some_and(|value| !value.starts_with("unix:///") || value.len() <= "unix:///".len())
        {
            bail!("SPIRE socket path must be an absolute unix:/// URI");
        }
        Ok(Self {
            workload_id,
            spiffe_id,
            spire_socket_path,
        })
    }
}

fn validate_spiffe_id(value: &str) -> Result<()> {
    if value.len() > 2048 || value.contains(['?', '#', '\\']) {
        bail!("invalid SPIFFE ID");
    }
    let rest = value
        .strip_prefix("spiffe://")
        .context("SPIFFE ID must start with spiffe://")?;
    let (trust_domain, path) = rest.split_once('/').unwrap_or((rest, ""));
    if trust_domain.is_empty()
        || trust_domain.len() > 255
        || trust_domain.split('.').any(|label| {
            label.is_empty()
                || !label.chars().all(|character| {
                    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
                })
                || label.starts_with('-')
                || label.ends_with('-')
        })
        || path
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        || path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        bail!("invalid SPIFFE ID");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionProfile {
    Observer,
    Collaborator,
    Operator,
}

impl PermissionProfile {
    pub fn actions(self) -> BTreeSet<String> {
        let read = [
            "identity.get",
            "tasks.ready",
            "memory.search",
            "inbox.list",
            "audit.tail",
            "audit.verify",
            "peers.list",
            "peers.join",
            "session.lock",
            "session.status",
            "session.unlock",
        ];
        let collaborate = [
            "tasks.create",
            "tasks.claim",
            "tasks.submit",
            "reviews.record",
            "memory.propose",
            "peer.send",
        ];
        let operator = [
            "invites.create",
            "delegations.approve",
            "delegations.revoke",
            "peers.block",
            "peers.unblock",
            "peers.revoke",
            "services.register",
        ];
        let delegated = ["delegations.request", "services.call", "services.grants"];
        read.into_iter()
            .chain(match self {
                Self::Observer => Vec::new(),
                Self::Collaborator | Self::Operator => collaborate.to_vec(),
            })
            .chain(match self {
                Self::Observer => Vec::new(),
                Self::Collaborator | Self::Operator => delegated.to_vec(),
            })
            .chain(match self {
                Self::Operator => operator.to_vec(),
                Self::Observer | Self::Collaborator => Vec::new(),
            })
            .map(str::to_owned)
            .collect()
    }
}

impl NodeConfig {
    pub fn new(
        organization: String,
        node_name: String,
        agent_id: String,
        permission_profile: PermissionProfile,
        notifications: bool,
        automatic_loop: bool,
        max_loop_iterations: u8,
    ) -> Result<Self> {
        if organization.trim().is_empty()
            || node_name.trim().is_empty()
            || agent_id.trim().is_empty()
        {
            bail!("organization, node name, and agent ID are required");
        }
        if automatic_loop && !(1..=10).contains(&max_loop_iterations) {
            bail!("automatic loop iterations must be between 1 and 10");
        }
        Ok(Self {
            version: 1,
            organization,
            node_name,
            agent_id,
            permission_profile,
            enabled_actions: permission_profile.actions(),
            notifications,
            automatic_loop,
            max_loop_iterations,
            session_minutes: default_session_minutes(),
            allow_agent_override: false,
            workload_identity: None,
        })
    }

    pub fn with_session_minutes(mut self, session_minutes: u16) -> Result<Self> {
        if !(5..=480).contains(&session_minutes) {
            bail!("agent session duration must be between 5 and 480 minutes");
        }
        self.session_minutes = session_minutes;
        Ok(self)
    }

    pub fn with_workload_identity(
        mut self,
        workload_id: String,
        spiffe_id: Option<String>,
        spire_socket_path: Option<String>,
    ) -> Result<Self> {
        self.workload_identity = Some(WorkloadIdentityConfig::new(
            workload_id,
            spiffe_id,
            spire_socket_path,
        )?);
        Ok(self)
    }

    pub fn developer(node_name: String) -> Self {
        Self {
            version: 1,
            organization: "development".to_owned(),
            node_name,
            agent_id: "agent:developer".to_owned(),
            permission_profile: PermissionProfile::Operator,
            enabled_actions: PermissionProfile::Operator.actions(),
            notifications: false,
            automatic_loop: false,
            max_loop_iterations: 3,
            session_minutes: 30,
            allow_agent_override: true,
            workload_identity: None,
        }
    }

    pub fn allows(&self, action: &str) -> bool {
        matches!(action, "health" | "identity.get") || self.enabled_actions.contains(action)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?
        };
        #[cfg(not(unix))]
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }
}

const fn default_session_minutes() -> u16 {
    30
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observer_is_read_only_and_loop_is_bounded() {
        let config = NodeConfig::new(
            "acme".into(),
            "node".into(),
            "agent:a".into(),
            PermissionProfile::Observer,
            false,
            false,
            3,
        )
        .unwrap();
        assert!(config.allows("memory.search"));
        assert!(!config.allows("memory.propose"));
        assert!(
            NodeConfig::new(
                "acme".into(),
                "node".into(),
                "agent:a".into(),
                PermissionProfile::Collaborator,
                false,
                true,
                11,
            )
            .is_err()
        );
    }

    #[test]
    fn workload_identity_accepts_spiffe_metadata_and_rejects_bad_ids() {
        let identity = WorkloadIdentityConfig::new(
            "worker:reviewer".into(),
            Some("spiffe://acme.example/company-mesh/reviewer".into()),
            Some("unix:///run/spire/sockets/agent.sock".into()),
        )
        .unwrap();
        assert_eq!(identity.workload_id, "worker:reviewer");
        assert!(
            WorkloadIdentityConfig::new(
                "worker".into(),
                Some("https://acme.example/worker".into()),
                None,
            )
            .is_err()
        );
        let legacy: NodeConfig = serde_json::from_value(serde_json::json!({
            "version": 1,
            "organization": "acme",
            "node_name": "legacy",
            "agent_id": "agent:legacy",
            "permission_profile": "observer",
            "enabled_actions": [],
            "notifications": false,
            "automatic_loop": false,
            "max_loop_iterations": 3
        }))
        .unwrap();
        assert!(legacy.workload_identity.is_none());
    }
}
