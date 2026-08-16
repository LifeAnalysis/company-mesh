use std::{
    collections::HashSet,
    io::IsTerminal,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use companyd::{
    config::{NodeConfig, PermissionProfile},
    identity::load_or_create_secret,
    passkey::{AdminApproval, authenticate_interactive, collect_assertion, register_interactive},
    service,
    store::Store,
};
use console::{Style, Term, style};
use dialoguer::{Select, theme::ColorfulTheme};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    process::Command,
};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "company-mesh",
    about = "Install and operate a Company Mesh node"
)]
struct Cli {
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Setup {
        #[arg(long)]
        organization: String,
        #[arg(long)]
        node_name: String,
        #[arg(long)]
        agent_id: String,
        /// Stable local workload name; defaults to the agent ID when SPIFFE fields are set.
        #[arg(long)]
        workload_id: Option<String>,
        /// Expected SPIFFE ID for a future SPIRE Workload API binding.
        #[arg(long, requires = "spire_socket_path")]
        spiffe_id: Option<String>,
        /// Future SPIRE Workload API socket URI, for example unix:///run/spire/agent.sock.
        #[arg(long, requires = "spiffe_id")]
        spire_socket_path: Option<String>,
        #[arg(long, value_enum)]
        permissions: Option<PermissionProfile>,
        #[arg(long, default_value_t = false)]
        notifications: bool,
        #[arg(long, default_value_t = false)]
        automatic_loop: bool,
        #[arg(long, default_value_t = 3)]
        max_loop_iterations: u8,
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u16).range(5..=480))]
        session_minutes: u16,
        #[arg(long)]
        configure_codex: bool,
        #[arg(long)]
        configure_claude_code: bool,
        #[arg(long)]
        configure_claude_desktop: bool,
        #[arg(long)]
        configure_all_clients: bool,
        #[arg(long)]
        mcp_adapter: Option<PathBuf>,
        #[arg(long)]
        install_service: bool,
        #[arg(long, hide = true)]
        dev_no_passkey: bool,
    },
    Invite {
        #[command(subcommand)]
        command: InviteCommand,
    },
    Join {
        #[arg(value_name = "TOKEN", conflicts_with_all = ["token_file", "stdin"])]
        token: Option<String>,
        #[arg(long, value_name = "FILE", conflicts_with_all = ["token", "stdin"])]
        token_file: Option<PathBuf>,
        #[arg(long, conflicts_with_all = ["token", "token_file"])]
        stdin: bool,
    },
    Peers {
        #[command(subcommand)]
        command: PeerCommand,
    },
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    Delegation {
        #[command(subcommand)]
        command: DelegationCommand,
    },
    Knowledge {
        #[command(subcommand)]
        command: KnowledgeCommand,
    },
    Loop {
        #[arg(long)]
        handler: PathBuf,
        #[arg(long = "handler-arg")]
        handler_args: Vec<String>,
        #[arg(long)]
        max_iterations: Option<u8>,
        #[arg(long, default_value_t = 300)]
        timeout_seconds: u64,
    },
    Status,
}

#[derive(Debug, Subcommand)]
enum InviteCommand {
    Create {
        #[arg(long)]
        invitee_label: String,
        #[arg(long = "scope", required = true)]
        scopes: Vec<String>,
        #[arg(long, default_value_t = 30)]
        rate_per_minute: u32,
        #[arg(long, default_value_t = 24)]
        expires_hours: i64,
    },
}

#[derive(Debug, Subcommand)]
enum PeerCommand {
    List,
    Block { endpoint_id: String },
    Unblock { endpoint_id: String },
    Revoke { endpoint_id: String },
}

#[derive(Debug, Subcommand)]
enum ServiceCommand {
    Install {
        #[arg(long)]
        companyd: Option<PathBuf>,
    },
    Uninstall,
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    Rotate {
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Debug, Subcommand)]
enum SessionCommand {
    Unlock,
    Status,
    Lock,
}

#[derive(Debug, Subcommand)]
enum DelegationCommand {
    RegisterService {
        #[arg(long)]
        name: String,
        #[arg(long)]
        executable: PathBuf,
        #[arg(long)]
        operations_json: PathBuf,
        #[arg(long, default_value_t = 60)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = 65_536)]
        max_output_bytes: usize,
        #[arg(long)]
        allow_network: bool,
        #[arg(long = "read-only-path")]
        read_only_paths: Vec<PathBuf>,
    },
    Approve {
        #[arg(long)]
        request_id: String,
        #[arg(long = "operation", required = true)]
        operations: Vec<String>,
        #[arg(long, default_value_t = 30)]
        expires_minutes: i64,
        #[arg(long, default_value_t = 3)]
        max_calls: u32,
    },
    Revoke {
        #[arg(long)]
        grant_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum KnowledgeCommand {
    /// Export memory records as JSON after removing secret-like values.
    Export {
        /// Owner-only output file. Omit to write JSON to standard output.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let data_dir = cli
        .data_dir
        .map(Ok)
        .unwrap_or_else(service::default_data_dir)?;
    match cli.command {
        Commands::Setup {
            organization,
            node_name,
            agent_id,
            workload_id,
            spiffe_id,
            spire_socket_path,
            permissions,
            notifications,
            automatic_loop,
            max_loop_iterations,
            session_minutes,
            configure_codex,
            configure_claude_code,
            configure_claude_desktop,
            configure_all_clients,
            mcp_adapter,
            install_service,
            dev_no_passkey,
        } => {
            if dev_no_passkey && !cfg!(debug_assertions) {
                bail!("--dev-no-passkey is unavailable in release builds");
            }
            setup_header();
            let permissions = choose_permissions(permissions)?;
            secure_data_dir(&data_dir)?;
            let passkey_path = data_dir.join("admin-passkeys.json");
            if !dev_no_passkey {
                if passkey_path.exists() {
                    step("Human approval", "Verify the administrator passkey");
                    authenticate_interactive(
                        &passkey_path,
                        "Change Company Mesh setup and permissions",
                    )
                    .await?;
                } else {
                    let existing_state = ["config.json", "identity.key", "state.db"]
                        .iter()
                        .any(|name| data_dir.join(name).exists());
                    if existing_state {
                        bail!(
                            "this existing node has no administrator passkey; automatic replacement is refused"
                        );
                    }
                    step("Human approval", "Create the administrator passkey");
                    register_interactive(&passkey_path, &agent_id).await?;
                }
            }
            let mut config = NodeConfig::new(
                organization,
                node_name,
                agent_id,
                permissions,
                notifications,
                automatic_loop,
                max_loop_iterations,
            )?
            .with_session_minutes(session_minutes)?;
            if workload_id.is_some() || spiffe_id.is_some() || spire_socket_path.is_some() {
                let workload_id = workload_id.unwrap_or_else(|| config.agent_id.clone());
                config =
                    config.with_workload_identity(workload_id, spiffe_id, spire_socket_path)?;
            }
            config.save(&data_dir.join("config.json"))?;
            let identity = load_or_create_secret(&data_dir.join("identity.key"))?;
            permission_summary(
                &config,
                &identity.public().to_string(),
                &data_dir,
                !dev_no_passkey,
            );
            if configure_codex || configure_all_clients {
                let adapter = mcp_adapter
                    .as_ref()
                    .context("--mcp-adapter is required when configuring clients")?;
                configure_codex_mcp(&data_dir, adapter, &config)?;
                println!("Configured Company Mesh for Codex and Codex CLI.");
            }
            if configure_claude_code || configure_all_clients {
                let adapter = mcp_adapter
                    .as_ref()
                    .context("--mcp-adapter is required when configuring clients")?;
                configure_claude_code_mcp(&data_dir, adapter, &config)?;
                println!("Configured Company Mesh for Claude Code.");
            }
            if configure_claude_desktop || configure_all_clients {
                let adapter = mcp_adapter
                    .as_ref()
                    .context("--mcp-adapter is required when configuring clients")?;
                let path = configure_claude_desktop_mcp(&data_dir, adapter, &config)?;
                println!("Configured Claude Desktop at {}.", path.display());
            }
            if install_service {
                let daemon = sibling_binary("companyd")?;
                let path = service::install(&data_dir, &daemon)?;
                println!("Installed user service at {}", path.display());
            }
        }
        Commands::Invite { command } => match command {
            InviteCommand::Create {
                invitee_label,
                scopes,
                rate_per_minute,
                expires_hours,
            } => {
                let result = rpc_admin(
                    &data_dir,
                    "invites.create",
                    json!({
                        "invitee_label": invitee_label,
                        "scopes": scopes,
                        "rate_per_minute": rate_per_minute,
                        "expires_hours": expires_hours,
                    }),
                )
                .await?;
                println!(
                    "{}",
                    result["token"]
                        .as_str()
                        .context("daemon omitted invite token")?
                );
            }
        },
        Commands::Join {
            token,
            token_file,
            stdin,
        } => {
            let token = read_invite_token(token, token_file, stdin)?;
            let result = rpc_admin(&data_dir, "peers.join", json!({"token": token})).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::Peers { command } => {
            let (method, params) = match command {
                PeerCommand::List => ("peers.list", json!({})),
                PeerCommand::Block { endpoint_id } => {
                    ("peers.block", json!({"endpoint_id": endpoint_id}))
                }
                PeerCommand::Unblock { endpoint_id } => {
                    ("peers.unblock", json!({"endpoint_id": endpoint_id}))
                }
                PeerCommand::Revoke { endpoint_id } => {
                    ("peers.revoke", json!({"endpoint_id": endpoint_id}))
                }
            };
            let result = if method == "peers.list" {
                rpc(&data_dir, method, params).await?
            } else {
                rpc_admin(&data_dir, method, params).await?
            };
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::Service { command } => match command {
            ServiceCommand::Install { companyd } => {
                let daemon = companyd
                    .map(Ok)
                    .unwrap_or_else(|| sibling_binary("companyd"))?;
                let path = service::install(&data_dir, &daemon)?;
                println!("Installed user service at {}", path.display());
            }
            ServiceCommand::Uninstall => {
                service::uninstall()?;
                println!("Removed the Company Mesh user service. Data was not removed.");
            }
        },
        Commands::Key { command } => match command {
            KeyCommand::Rotate { confirm } => {
                authenticate_interactive(
                    &data_dir.join("admin-passkeys.json"),
                    "Rotate the Iroh identity and archive current peer state",
                )
                .await?;
                rotate_key(&data_dir, confirm)?;
            }
        },
        Commands::Session { command } => {
            let (method, protected) = match command {
                SessionCommand::Unlock => ("session.unlock", true),
                SessionCommand::Status => ("session.status", false),
                SessionCommand::Lock => ("session.lock", false),
            };
            let result = if protected {
                rpc_admin(&data_dir, method, json!({})).await?
            } else {
                rpc(&data_dir, method, json!({})).await?
            };
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::Delegation { command } => match command {
            DelegationCommand::RegisterService {
                name,
                executable,
                operations_json,
                timeout_seconds,
                max_output_bytes,
                allow_network,
                read_only_paths,
            } => {
                let operations: std::collections::BTreeMap<String, Vec<String>> =
                    serde_json::from_slice(&std::fs::read(&operations_json)?)?;
                let result = rpc_admin(
                    &data_dir,
                    "services.register",
                    json!({"name":name,"executable":executable,"operations":operations,
                        "timeout_seconds":timeout_seconds,"max_output_bytes":max_output_bytes,
                        "allow_network":allow_network,"read_only_paths":read_only_paths}),
                )
                .await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            DelegationCommand::Approve {
                request_id,
                operations,
                expires_minutes,
                max_calls,
            } => {
                let result = rpc_admin(
                    &data_dir,
                    "delegations.approve",
                    json!({"request_id":request_id,"operations":operations,
                        "expires_minutes":expires_minutes,"max_calls":max_calls}),
                )
                .await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            DelegationCommand::Revoke { grant_id } => {
                let result = rpc_admin(
                    &data_dir,
                    "delegations.revoke",
                    json!({"grant_id":grant_id}),
                )
                .await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
        },
        Commands::Knowledge { command } => match command {
            KnowledgeCommand::Export { output } => {
                let identity_path = data_dir.join("identity.key");
                let database_path = data_dir.join("state.db");
                let config_path = data_dir.join("config.json");
                if !identity_path.exists() || !database_path.exists() {
                    bail!("knowledge export requires an existing configured knowledge base");
                }
                if output.as_ref().is_some_and(|path| {
                    path == &identity_path || path == &database_path || path == &config_path
                }) {
                    bail!("refusing to overwrite Company Mesh state with an export");
                }
                let secret = load_or_create_secret(&identity_path)?;
                let store = Store::open(&database_path, secret)?;
                let bytes = serde_json::to_vec_pretty(&store.export_knowledge_redacted()?)?;
                if let Some(path) = output {
                    let data_root = std::fs::canonicalize(&data_dir)?;
                    let output_parent = std::fs::canonicalize(
                        path.parent()
                            .context("knowledge export path has no parent")?,
                    )?;
                    if output_parent.starts_with(&data_root) {
                        bail!(
                            "refusing to write a knowledge export inside the node data directory"
                        );
                    }
                    write_owner_file(&path, &bytes)?;
                    println!("Exported redacted knowledge to {}.", path.display());
                } else {
                    println!("{}", String::from_utf8(bytes)?);
                }
            }
        },
        Commands::Loop {
            handler,
            handler_args,
            max_iterations,
            timeout_seconds,
        } => {
            run_loop(
                &data_dir,
                &handler,
                &handler_args,
                max_iterations,
                timeout_seconds,
            )
            .await?;
        }
        Commands::Status => {
            println!(
                "{}",
                serde_json::to_string_pretty(&rpc(&data_dir, "identity.get", json!({})).await?)?
            );
        }
    }
    Ok(())
}

fn read_invite_token(
    token: Option<String>,
    token_file: Option<PathBuf>,
    stdin: bool,
) -> Result<String> {
    let value = if let Some(path) = token_file {
        std::fs::read_to_string(&path)
            .with_context(|| format!("read invite token from {}", path.display()))?
    } else if stdin {
        use std::io::Read;
        let mut value = String::new();
        std::io::stdin().read_to_string(&mut value)?;
        value
    } else if let Some(token) = token {
        token
    } else {
        bail!("provide TOKEN, --token-file FILE, or --stdin");
    };
    let value = value.trim().to_owned();
    if value.is_empty() {
        bail!("invite token is empty");
    }
    Ok(value)
}

fn choose_permissions(profile: Option<PermissionProfile>) -> Result<PermissionProfile> {
    if let Some(profile) = profile {
        return Ok(profile);
    }
    if !std::io::stdin().is_terminal() {
        bail!("--permissions is required in non-interactive setup");
    }
    let items = [
        "Observer      Read identity, tasks, memory, inbox, peers, and audit",
        "Collaborator  Observer access plus work, review, memory, and messages",
        "Operator      Collaborator access plus invites, blocking, and revocation",
    ];
    let selected = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose local agent permissions")
        .items(items)
        .default(0)
        .interact()?;
    Ok(match selected {
        0 => PermissionProfile::Observer,
        1 => PermissionProfile::Collaborator,
        2 => PermissionProfile::Operator,
        _ => unreachable!("dialoguer returned an invalid selection"),
    })
}

fn setup_header() {
    let term = Term::stderr();
    let accent = Style::new().color256(118).bold();
    let _ = term.write_line("");
    let _ = term.write_line(&accent.apply_to("  COMPANY MESH").to_string());
    let _ = term.write_line(&style("  Secure agent-to-agent setup").dim().to_string());
    let _ = term.write_line(&style("  ───────────────────────────").dim().to_string());
    let _ = term.write_line("");
}

fn step(name: &str, detail: &str) {
    eprintln!("{}  {}", style("◆").color256(118), style(name).bold());
    eprintln!("   {}", style(detail).dim());
}

fn permission_summary(config: &NodeConfig, endpoint: &str, data_dir: &Path, passkey_enabled: bool) {
    eprintln!();
    eprintln!(
        "{} {}",
        style("✓").color256(118).bold(),
        style("Node configured").bold()
    );
    eprintln!(
        "  Profile       {}",
        profile_name(config.permission_profile)
    );
    eprintln!("  Agent         {}", config.agent_id);
    if let Some(workload) = &config.workload_identity {
        eprintln!("  Workload      {}", workload.workload_id);
        if let Some(spiffe_id) = &workload.spiffe_id {
            eprintln!("  SPIFFE ID     {spiffe_id}");
        }
    }
    eprintln!("  Endpoint      {endpoint}");
    eprintln!("  Data          {}", data_dir.display());
    eprintln!("  Notifications {}", on_off(config.notifications));
    eprintln!("  Agent loop    {}", on_off(config.automatic_loop));
    eprintln!("  Session       {} minutes", config.session_minutes);
    eprintln!("  Passkey gate  {}", on_off(passkey_enabled));
    eprintln!();
    eprintln!("{}", style("Access").bold());
    eprintln!("  {}", profile_summary(config.permission_profile));
    eprintln!(
        "  {} policy-checked actions enabled",
        config.enabled_actions.len()
    );
    eprintln!();
    eprintln!("{}", style("Next").bold());
    eprintln!("  1. Start the daemon or install the user service.");
    eprintln!("  2. Run `company-mesh session unlock` before agent writes.");
    eprintln!("  3. Run `company-mesh status` to check the node.");
    eprintln!();
}

fn profile_name(profile: PermissionProfile) -> &'static str {
    match profile {
        PermissionProfile::Observer => "Observer",
        PermissionProfile::Collaborator => "Collaborator",
        PermissionProfile::Operator => "Operator",
    }
}

fn profile_summary(profile: PermissionProfile) -> &'static str {
    match profile {
        PermissionProfile::Observer => "Read identity, tasks, memory, peers, inbox, and audit.",
        PermissionProfile::Collaborator => {
            "Read and collaborate on tasks, reviews, memory, and messages."
        }
        PermissionProfile::Operator => {
            "Collaborate and administer enrollment, peers, and services."
        }
    }
}

fn on_off(value: bool) -> &'static str {
    if value { "enabled" } else { "disabled" }
}

fn secure_data_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn sibling_binary(name: &str) -> Result<PathBuf> {
    let current = std::env::current_exe()?;
    let sibling = current.with_file_name(name);
    if !sibling.exists() {
        bail!("required binary does not exist at {}", sibling.display());
    }
    Ok(sibling)
}

fn configure_codex_mcp(data_dir: &Path, adapter: &Path, config: &NodeConfig) -> Result<()> {
    if !adapter.is_absolute() || !adapter.exists() {
        bail!("MCP adapter must be an existing absolute path");
    }
    let socket = data_dir.join("companyd.sock");
    let _ = std::process::Command::new("codex")
        .args(["mcp", "remove", "company-mesh"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let status = std::process::Command::new("codex")
        .args(["mcp", "add", "company-mesh"])
        .arg("--env")
        .arg(format!("COMPANY_MESH_SOCKET={}", socket.display()))
        .arg("--env")
        .arg(format!("COMPANY_AGENT_ID={}", config.agent_id))
        .arg("--env")
        .arg(format!(
            "COMPANY_PERMISSION_PROFILE={}",
            format!("{:?}", config.permission_profile).to_lowercase()
        ))
        .args(["--", "node"])
        .arg(adapter)
        .status()
        .context("run codex mcp add")?;
    if !status.success() {
        bail!("Codex MCP configuration failed");
    }
    Ok(())
}

fn configure_claude_code_mcp(data_dir: &Path, adapter: &Path, config: &NodeConfig) -> Result<()> {
    validate_adapter(adapter)?;
    let socket = data_dir.join("companyd.sock");
    let _ = std::process::Command::new("claude")
        .args(["mcp", "remove", "company-mesh", "-s", "user"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let status = std::process::Command::new("claude")
        .args(["mcp", "add", "--transport", "stdio"])
        .arg("--env")
        .arg(format!("COMPANY_MESH_SOCKET={}", socket.display()))
        .arg("--env")
        .arg(format!("COMPANY_AGENT_ID={}", config.agent_id))
        .arg("--env")
        .arg(format!(
            "COMPANY_PERMISSION_PROFILE={}",
            format!("{:?}", config.permission_profile).to_lowercase()
        ))
        .args(["--scope", "user", "company-mesh", "--", "node"])
        .arg(adapter)
        .status()
        .context("run claude mcp add")?;
    if !status.success() {
        bail!("Claude Code MCP configuration failed");
    }
    Ok(())
}

fn configure_claude_desktop_mcp(
    data_dir: &Path,
    adapter: &Path,
    config: &NodeConfig,
) -> Result<PathBuf> {
    validate_adapter(adapter)?;
    #[cfg(target_os = "macos")]
    let path = dirs::home_dir()
        .context("cannot determine the home directory")?
        .join("Library/Application Support/Claude/claude_desktop_config.json");
    #[cfg(target_os = "linux")]
    let path = dirs::config_dir()
        .context("cannot determine the config directory")?
        .join("Claude/claude_desktop_config.json");
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    bail!("automatic Claude Desktop configuration supports macOS and Linux only");
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let mut root: Value = if path.exists() {
            serde_json::from_slice(&std::fs::read(&path)?)?
        } else {
            json!({})
        };
        let root_object = root
            .as_object_mut()
            .context("Claude Desktop configuration must be a JSON object")?;
        let servers = root_object
            .entry("mcpServers")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .context("Claude Desktop mcpServers must be a JSON object")?;
        servers.insert(
            "company-mesh".to_owned(),
            json!({
                "type": "stdio",
                "command": "node",
                "args": [adapter],
                "env": {
                    "COMPANY_MESH_SOCKET": data_dir.join("companyd.sock"),
                    "COMPANY_AGENT_ID": config.agent_id,
                    "COMPANY_PERMISSION_PROFILE": format!("{:?}", config.permission_profile).to_lowercase(),
                }
            }),
        );
        std::fs::create_dir_all(path.parent().context("invalid Claude Desktop path")?)?;
        write_owner_file(&path, &serde_json::to_vec_pretty(&root)?)?;
        Ok(path)
    }
}

fn validate_adapter(adapter: &Path) -> Result<()> {
    if !adapter.is_absolute() || !adapter.exists() {
        bail!("MCP adapter must be an existing absolute path");
    }
    Ok(())
}

fn write_owner_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::{fs::OpenOptions, io::Write};
    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        bail!(
            "refusing to write through a symbolic link: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file
    };
    #[cfg(not(unix))]
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

async fn rpc(data_dir: &Path, method: &str, params: Value) -> Result<Value> {
    rpc_with_approval(data_dir, method, params, None).await
}

async fn rpc_admin(data_dir: &Path, method: &str, params: Value) -> Result<Value> {
    let challenge = rpc(data_dir, "admin.challenge", json!({"action": method})).await?;
    if challenge["development_bypass"] == true {
        return rpc_with_approval(data_dir, method, params, None).await;
    }
    let challenge_id: Uuid = serde_json::from_value(challenge["challenge_id"].clone())?;
    let credential = collect_assertion(challenge["options"].clone(), method).await?;
    rpc_with_approval(
        data_dir,
        method,
        params,
        Some(AdminApproval {
            challenge_id,
            action: method.to_owned(),
            credential,
        }),
    )
    .await
}

async fn rpc_with_approval(
    data_dir: &Path,
    method: &str,
    params: Value,
    approval: Option<AdminApproval>,
) -> Result<Value> {
    let config = NodeConfig::load(&data_dir.join("config.json"))?;
    let stream = UnixStream::connect(data_dir.join("companyd.sock"))
        .await
        .context("connect to companyd; start the user service first")?;
    let (read, mut write) = stream.into_split();
    let id = Uuid::new_v4().to_string();
    write
        .write_all(
            format!(
                "{}\n",
                json!({
                    "id": id,
                    "method": method,
                    "params": params,
                    "agent_id": config.agent_id,
                    "approval": approval,
                })
            )
            .as_bytes(),
        )
        .await?;
    let mut lines = BufReader::new(read).lines();
    let line = lines
        .next_line()
        .await?
        .context("companyd closed without a response")?;
    #[derive(Deserialize)]
    struct Response {
        id: Value,
        ok: bool,
        result: Option<Value>,
        error: Option<Value>,
    }
    let response: Response = serde_json::from_str(&line)?;
    if response.id != id {
        bail!("companyd returned a mismatched response ID");
    }
    if !response.ok {
        bail!(
            "companyd rejected the request: {}",
            response.error.unwrap_or(Value::Null)
        );
    }
    Ok(response.result.unwrap_or(Value::Null))
}

async fn run_loop(
    data_dir: &Path,
    handler: &Path,
    handler_args: &[String],
    requested_max: Option<u8>,
    timeout_seconds: u64,
) -> Result<()> {
    let config = NodeConfig::load(&data_dir.join("config.json"))?;
    if !config.automatic_loop {
        bail!("automatic loop permission is disabled; run setup again to enable it");
    }
    if !handler.is_absolute() || !handler.exists() {
        bail!("loop handler must be an existing absolute executable path");
    }
    let max = requested_max
        .unwrap_or(config.max_loop_iterations)
        .min(config.max_loop_iterations);
    let cursor_path = data_dir.join("loop-processed.json");
    let mut processed: HashSet<String> = if cursor_path.exists() {
        serde_json::from_slice(&std::fs::read(&cursor_path)?)?
    } else {
        HashSet::new()
    };
    let mut inbox = rpc(data_dir, "inbox.list", json!({"limit": 100})).await?;
    let messages = inbox.as_array_mut().context("invalid inbox response")?;
    messages.reverse();
    let mut completed = 0u8;
    for message in messages {
        let message_id = message["message_id"]
            .as_str()
            .context("message has no ID")?;
        if processed.contains(message_id) || completed >= max {
            continue;
        }
        let mut child = Command::new(handler)
            .args(handler_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        child
            .stdin
            .take()
            .context("handler stdin is unavailable")?
            .write_all(&serde_json::to_vec(message)?)
            .await?;
        let output = tokio::time::timeout(
            Duration::from_secs(timeout_seconds.min(900)),
            child.wait_with_output(),
        )
        .await
        .context("loop handler timed out")??;
        if !output.status.success() || output.stdout.len() > 1_048_576 {
            bail!("loop handler failed or exceeded the output limit");
        }
        let decision: Value =
            serde_json::from_slice(&output.stdout).context("handler must return JSON")?;
        if let Some(reply) = decision["reply"]
            .as_str()
            .filter(|reply| !reply.trim().is_empty())
        {
            rpc(
                data_dir,
                "peer.send",
                json!({
                    "endpoint_addr": message["sender_addr"],
                    "scope": message["scope"],
                    "message": reply,
                }),
            )
            .await?;
        }
        processed.insert(message_id.to_owned());
        completed += 1;
    }
    std::fs::write(&cursor_path, serde_json::to_vec_pretty(&processed)?)?;
    println!("Processed {completed} message(s). Maximum was {max}.");
    Ok(())
}

fn rotate_key(data_dir: &Path, confirm: bool) -> Result<()> {
    if !confirm {
        bail!("key rotation changes the endpoint ID; pass --confirm after you notify peers");
    }
    if data_dir.join("companyd.sock").exists() {
        bail!("stop companyd before key rotation");
    }
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let archive = data_dir.join("rotation-archive").join(stamp);
    std::fs::create_dir_all(&archive)?;
    for name in ["identity.key", "state.db", "state.db-wal", "state.db-shm"] {
        let source = data_dir.join(name);
        if source.exists() {
            std::fs::rename(&source, archive.join(name))?;
        }
    }
    let secret = load_or_create_secret(&data_dir.join("identity.key"))?;
    println!("New endpoint: {}", secret.public());
    println!("Old identity and state moved to {}", archive.display());
    println!("All peers must enroll again.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knowledge_export_command_accepts_stdout_or_owner_file() {
        let stdout = Cli::try_parse_from(["company-mesh", "knowledge", "export"]).unwrap();
        assert!(matches!(
            stdout.command,
            Commands::Knowledge {
                command: KnowledgeCommand::Export { output: None }
            }
        ));
        let file = Cli::try_parse_from([
            "company-mesh",
            "knowledge",
            "export",
            "--output",
            "/tmp/knowledge.json",
        ])
        .unwrap();
        assert!(matches!(
            file.command,
            Commands::Knowledge {
                command: KnowledgeCommand::Export { output: Some(_) }
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn owner_file_refuses_a_symbolic_link() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        symlink(&target, &link).unwrap();
        assert!(write_owner_file(&link, b"safe output").is_err());
        assert!(!target.exists());
    }
}
