use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result, bail};
use clap::Parser;
use tokio::sync::Mutex;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use companyd::{
    config::NodeConfig,
    identity::load_or_create_secret,
    model,
    network::{accept_loop, build_endpoint},
    passkey::AdminGate,
    rpc::{AppState, serve_local_socket},
    store::Store,
};

#[derive(Debug, Parser)]
#[command(name = "companyd", about = "Local-first company agent mesh daemon")]
struct Args {
    #[arg(long, default_value = ".company-mesh")]
    data_dir: PathBuf,
    #[arg(long)]
    socket: Option<PathBuf>,
    #[arg(long, default_value = "local-node")]
    node_name: String,
    #[arg(long)]
    dev_mode: bool,
    #[arg(long)]
    no_relay: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("companyd=info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    if args.dev_mode && !cfg!(debug_assertions) {
        bail!("--dev-mode is unavailable in release builds");
    }
    std::fs::create_dir_all(&args.data_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&args.data_dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let socket = args
        .socket
        .unwrap_or_else(|| args.data_dir.join("companyd.sock"));
    let config_path = args.data_dir.join("config.json");
    let config = if args.dev_mode {
        NodeConfig::developer(args.node_name.clone())
    } else {
        NodeConfig::load(&config_path).with_context(|| {
            format!(
                "setup is required; run company-mesh setup --data-dir {}",
                args.data_dir.display()
            )
        })?
    };
    let secret = load_or_create_secret(&args.data_dir.join("identity.key"))?;
    let admin_gate = if args.dev_mode {
        None
    } else {
        Some(Arc::new(Mutex::new(
            AdminGate::load(&args.data_dir.join("admin-passkeys.json"))
                .context("administrator passkey is required; run company-mesh setup first")?,
        )))
    };
    let store = Arc::new(Mutex::new(Store::open(
        &args.data_dir.join("state.db"),
        secret.clone(),
    )?));
    let endpoint = build_endpoint(secret.clone(), !args.no_relay).await?;
    if !args.no_relay {
        endpoint.online().await;
    }
    let identity = serde_json::json!({
        "node_name": config.node_name,
        "endpoint_id": endpoint.id().to_string(),
        "endpoint_addr": endpoint.addr(),
        "socket": socket,
        "protocol": model::PROTOCOL,
        "workload_identity": config.workload_identity,
    });
    println!("{}", serde_json::to_string(&identity)?);
    info!(endpoint_id=%endpoint.id(), socket=%socket.display(), "companyd ready");

    let network_task = tokio::spawn(accept_loop(
        endpoint.clone(),
        store.clone(),
        config.notifications,
    ));
    let rpc_state = AppState {
        node_name: config.node_name.clone(),
        config,
        secret,
        endpoint: endpoint.clone(),
        store,
        admin_gate,
    };
    let rpc_task = tokio::spawn({
        let socket = socket.clone();
        async move { serve_local_socket(&socket, rpc_state).await }
    });

    tokio::select! {
        result = network_task => result??,
        result = rpc_task => result??,
        _ = tokio::signal::ctrl_c() => info!("shutdown requested"),
    }
    endpoint.close().await;
    if socket.exists()
        && let Err(error) = std::fs::remove_file(&socket)
    {
        error!(%error, socket=%socket.display(), "failed to remove local socket");
    }
    Ok(())
}
