use std::{collections::HashMap, fs::OpenOptions, io::Write, path::Path, sync::Arc};

use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::State,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{Mutex, oneshot};
use uuid::Uuid;
use webauthn_rs::prelude::*;

const CEREMONY_ADDR: &str = "127.0.0.1:39271";
const ORIGIN: &str = "http://localhost:39271";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyStore {
    pub user_id: Uuid,
    pub username: String,
    pub passkeys: Vec<Passkey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminApproval {
    pub challenge_id: Uuid,
    pub action: String,
    pub credential: PublicKeyCredential,
}

struct PendingApproval {
    action: String,
    expires_at: DateTime<Utc>,
    state: PasskeyAuthentication,
}

#[derive(Debug, Clone)]
struct AgentSession {
    opened_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionScope {
    Routine,
    External,
}

pub struct AdminGate {
    webauthn: Webauthn,
    store: PasskeyStore,
    store_path: std::path::PathBuf,
    pending: HashMap<Uuid, PendingApproval>,
    routine_session: Option<AgentSession>,
    external_session: Option<AgentSession>,
}

impl AdminGate {
    pub fn load(path: &Path) -> Result<Self> {
        let store = load_store(path)?;
        Ok(Self {
            webauthn: webauthn()?,
            store,
            store_path: path.to_owned(),
            pending: HashMap::new(),
            routine_session: None,
            external_session: None,
        })
    }

    pub fn begin(&mut self, action: &str) -> Result<Value> {
        self.pending
            .retain(|_, value| value.expires_at > Utc::now());
        if self.pending.len() >= 10 {
            bail!("too many pending passkey ceremonies");
        }
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&self.store.passkeys)?;
        let challenge_id = Uuid::new_v4();
        self.pending.insert(
            challenge_id,
            PendingApproval {
                action: action.to_owned(),
                expires_at: Utc::now() + chrono::Duration::minutes(3),
                state,
            },
        );
        Ok(json!({
            "challenge_id": challenge_id,
            "binding": action,
            "expires_in_seconds": 180,
            "options": require_user_verification(serde_json::to_value(options)?)?,
        }))
    }

    pub fn verify(&mut self, approval: AdminApproval, expected_action: &str) -> Result<()> {
        let pending = self
            .pending
            .remove(&approval.challenge_id)
            .context("passkey challenge is unknown or already used")?;
        if pending.expires_at < Utc::now()
            || pending.action != expected_action
            || approval.action != expected_action
        {
            bail!("passkey approval is expired or bound to another action");
        }
        let result = self
            .webauthn
            .finish_passkey_authentication(&approval.credential, &pending.state)?;
        for passkey in &mut self.store.passkeys {
            passkey.update_credential(&result);
        }
        save_store(&self.store_path, &self.store)?;
        Ok(())
    }

    pub fn open_agent_session(&mut self, scope: SessionScope, minutes: u16) -> Result<Value> {
        if !(5..=480).contains(&minutes) {
            bail!("agent session duration must be between 5 and 480 minutes");
        }
        let opened_at = Utc::now();
        let expires_at = opened_at + chrono::Duration::minutes(i64::from(minutes));
        let session = AgentSession {
            opened_at,
            expires_at,
        };
        *self.session_mut(scope) = Some(session);
        Ok(json!({
            "unlocked": true,
            "scope": scope.name(),
            "opened_at": opened_at,
            "expires_at": expires_at,
            "session_minutes": minutes,
        }))
    }

    pub fn agent_session_status(&mut self, scope: SessionScope) -> Value {
        let now = Utc::now();
        if self
            .session(scope)
            .as_ref()
            .is_some_and(|session| session.expires_at <= now)
        {
            *self.session_mut(scope) = None;
        }
        match self.session(scope) {
            Some(session) => json!({
                "unlocked": true,
                "scope": scope.name(),
                "opened_at": session.opened_at,
                "expires_at": session.expires_at,
                "remaining_seconds": (session.expires_at - now).num_seconds().max(0),
            }),
            None => json!({"unlocked": false, "scope": scope.name()}),
        }
    }

    pub fn require_agent_session(&mut self, scope: SessionScope) -> Result<()> {
        if self.agent_session_status(scope)["unlocked"] != true {
            bail!(
                "{} session is locked or expired; run company-mesh session {}",
                scope.name(),
                scope.unlock_command()
            );
        }
        Ok(())
    }

    pub fn session_status(&mut self) -> Value {
        json!({
            "routine": self.agent_session_status(SessionScope::Routine),
            "external": self.agent_session_status(SessionScope::External),
        })
    }

    pub fn lock_agent_sessions(&mut self) -> Value {
        self.routine_session = None;
        self.external_session = None;
        json!({
            "routine": {"unlocked": false, "scope": "routine"},
            "external": {"unlocked": false, "scope": "external"},
        })
    }

    fn session(&self, scope: SessionScope) -> &Option<AgentSession> {
        match scope {
            SessionScope::Routine => &self.routine_session,
            SessionScope::External => &self.external_session,
        }
    }

    fn session_mut(&mut self, scope: SessionScope) -> &mut Option<AgentSession> {
        match scope {
            SessionScope::Routine => &mut self.routine_session,
            SessionScope::External => &mut self.external_session,
        }
    }
}

impl SessionScope {
    fn name(self) -> &'static str {
        match self {
            Self::Routine => "routine",
            Self::External => "external",
        }
    }

    fn unlock_command(self) -> &'static str {
        match self {
            Self::Routine => "unlock",
            Self::External => "unlock-external",
        }
    }
}

pub async fn register_interactive(path: &Path, username: &str) -> Result<()> {
    if path.exists() {
        bail!("an administrator passkey is already enrolled");
    }
    let webauthn = webauthn()?;
    let user_id = Uuid::new_v4();
    let (options, state) =
        webauthn.start_passkey_registration(user_id, username, username, None)?;
    let credential = browser_ceremony(
        platform_registration_options(serde_json::to_value(options)?)?,
        "Create administrator passkey",
        "Use Touch ID or this device's verified platform authenticator.",
        CeremonyKind::Registration,
    )
    .await?;
    let credential: RegisterPublicKeyCredential = serde_json::from_value(credential)?;
    let passkey = webauthn.finish_passkey_registration(&credential, &state)?;
    save_store(
        path,
        &PasskeyStore {
            user_id,
            username: username.to_owned(),
            passkeys: vec![passkey],
        },
    )?;
    Ok(())
}

pub async fn authenticate_interactive(path: &Path, action: &str) -> Result<()> {
    let mut store = load_store(path)?;
    let webauthn = webauthn()?;
    let (options, state) = webauthn.start_passkey_authentication(&store.passkeys)?;
    let credential = browser_ceremony(
        require_user_verification(serde_json::to_value(options)?)?,
        "Approve protected action",
        action,
        CeremonyKind::Authentication,
    )
    .await?;
    let credential: PublicKeyCredential = serde_json::from_value(credential)?;
    let result = webauthn.finish_passkey_authentication(&credential, &state)?;
    for passkey in &mut store.passkeys {
        passkey.update_credential(&result);
    }
    save_store(path, &store)
}

pub async fn collect_assertion(options: Value, action: &str) -> Result<PublicKeyCredential> {
    let value = browser_ceremony(
        require_user_verification(options)?,
        "Approve Company Mesh action",
        action,
        CeremonyKind::Authentication,
    )
    .await?;
    serde_json::from_value(value).map_err(Into::into)
}

fn require_user_verification(mut options: Value) -> Result<Value> {
    let public_key = options
        .get_mut("publicKey")
        .and_then(Value::as_object_mut)
        .context("WebAuthn options omitted publicKey")?;
    public_key.insert("userVerification".to_owned(), json!("required"));
    Ok(options)
}

fn platform_registration_options(mut options: Value) -> Result<Value> {
    let public_key = options
        .get_mut("publicKey")
        .and_then(Value::as_object_mut)
        .context("WebAuthn registration options omitted publicKey")?;
    let selection = public_key
        .entry("authenticatorSelection")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .context("invalid authenticatorSelection")?;
    selection.insert("authenticatorAttachment".to_owned(), json!("platform"));
    selection.insert("userVerification".to_owned(), json!("required"));
    Ok(options)
}

#[derive(Clone, Copy)]
enum CeremonyKind {
    Registration,
    Authentication,
}

#[derive(Clone)]
struct BrowserState {
    options: Value,
    html: Arc<String>,
    result: Arc<Mutex<Option<oneshot::Sender<Value>>>>,
}

async fn browser_ceremony(
    options: Value,
    title: &str,
    detail: &str,
    kind: CeremonyKind,
) -> Result<Value> {
    let listener = tokio::net::TcpListener::bind(CEREMONY_ADDR)
        .await
        .context("passkey setup port 39271 is in use")?;
    let (result_tx, result_rx) = oneshot::channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let state = BrowserState {
        options,
        html: Arc::new(ceremony_html(title, detail, kind)),
        result: Arc::new(Mutex::new(Some(result_tx))),
    };
    let app = Router::new()
        .route("/", get(page))
        .route("/options", get(get_options))
        .route("/finish", post(finish))
        .with_state(state);
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
    });
    open_browser(ORIGIN)?;
    let result = tokio::time::timeout(std::time::Duration::from_secs(180), result_rx)
        .await
        .context("passkey ceremony timed out")?
        .context("passkey browser closed without a result")?;
    let _ = shutdown_tx.send(());
    server.await??;
    if let Some(error) = result.get("ceremony_error").and_then(Value::as_str) {
        bail!("passkey ceremony failed: {error}");
    }
    Ok(result)
}

async fn page(State(state): State<BrowserState>) -> Html<String> {
    Html((*state.html).clone())
}

async fn get_options(State(state): State<BrowserState>) -> Json<Value> {
    Json(state.options)
}

async fn finish(State(state): State<BrowserState>, Json(value): Json<Value>) -> impl IntoResponse {
    if let Some(sender) = state.result.lock().await.take() {
        let _ = sender.send(value);
    }
    Html("<main><h1>Approved</h1><p>You can close this tab.</p></main>")
}

fn ceremony_html(title: &str, detail: &str, kind: CeremonyKind) -> String {
    let title = json_for_script(title);
    let detail = json_for_script(detail);
    let operation = match kind {
        CeremonyKind::Registration => "create",
        CeremonyKind::Authentication => "get",
    };
    format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Company Mesh passkey</title><style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#090b10;color:#f4f1e8;font:16px/1.5 ui-sans-serif,system-ui}}
main{{width:min(560px,calc(100% - 32px));padding:42px;border:1px solid #2a303c;border-radius:24px;background:linear-gradient(145deg,#151922,#0d1016);box-shadow:0 28px 80px #0008}}
.mark{{width:48px;height:48px;border-radius:15px;display:grid;place-items:center;background:#b8ff5a;color:#0a0c0f;font-weight:900;box-shadow:0 0 36px #b8ff5a44}}h1{{font-size:32px;line-height:1.1;margin:28px 0 12px}}p{{color:#aeb6c5}}button{{width:100%;margin-top:24px;padding:15px;border:0;border-radius:13px;background:#b8ff5a;color:#10130d;font:700 16px system-ui;cursor:pointer}}button:disabled{{opacity:.55}}#status{{min-height:24px;font-size:14px}}
</style></head><body><main><div class="mark">CM</div><h1 id="title"></h1><p id="detail"></p><button id="approve">Continue with passkey</button><p id="status">A human approval is required.</p></main>
<script>
const title={title},detail={detail},operation={operation:?};
document.querySelector('#title').textContent=title;document.querySelector('#detail').textContent=detail;
const fromB64=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(s.length/4)*4,'=')),c=>c.charCodeAt(0));
const toB64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
document.querySelector('#approve').onclick=async()=>{{const btn=document.querySelector('#approve'),status=document.querySelector('#status');btn.disabled=true;status.textContent='Waiting for your passkey…';try{{const o=await(await fetch('/options')).json();o.publicKey.challenge=fromB64(o.publicKey.challenge);if(o.publicKey.user)o.publicKey.user.id=fromB64(o.publicKey.user.id);for(const c of o.publicKey.excludeCredentials||[])c.id=fromB64(c.id);for(const c of o.publicKey.allowCredentials||[])c.id=fromB64(c.id);const c=await navigator.credentials[operation](o);const response={{clientDataJSON:toB64(c.response.clientDataJSON)}};if(operation==='create'){{response.attestationObject=toB64(c.response.attestationObject);response.transports=c.response.getTransports?c.response.getTransports():[]}}else{{response.authenticatorData=toB64(c.response.authenticatorData);response.signature=toB64(c.response.signature);response.userHandle=c.response.userHandle?toB64(c.response.userHandle):null}}const body={{id:c.id,rawId:toB64(c.rawId),type:c.type,response,extensions:c.getClientExtensionResults()}};await fetch('/finish',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify(body)}});document.body.innerHTML='<main><div class="mark">✓</div><h1>Approved</h1><p>You can close this tab.</p></main>'}}catch(e){{status.textContent=e.message;btn.disabled=false;await fetch('/finish',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify({{ceremony_error:e.message}})}})}}}};
</script></body></html>"#
    )
}

fn json_for_script(value: &str) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| "\"\"".to_owned())
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

fn webauthn() -> Result<Webauthn> {
    let origin = Url::parse(ORIGIN)?;
    Ok(WebauthnBuilder::new("localhost", &origin)?
        .rp_name("Company Mesh administrator")
        .build()?)
}

fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    let status = std::process::Command::new("open").arg(url).status()?;
    #[cfg(target_os = "linux")]
    let status = std::process::Command::new("xdg-open").arg(url).status()?;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    bail!("open {url} in a browser to continue");
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if !status.success() {
        bail!("could not open the passkey page at {url}");
    }
    Ok(())
}

fn load_store(path: &Path) -> Result<PasskeyStore> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

fn save_store(path: &Path, store: &PasskeyStore) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(store)?;
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
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};

    #[test]
    fn ceremony_page_contains_no_unescaped_action_markup() {
        let html = ceremony_html(
            "Approve",
            "</script><script>alert(1)</script>",
            CeremonyKind::Authentication,
        );
        assert!(!html.contains("const detail=\"</script>"));
    }

    #[test]
    fn registration_prefers_platform_and_requires_verification() {
        let options = json!({"publicKey": {"challenge": "test"}});
        let options = platform_registration_options(options).unwrap();
        assert_eq!(
            options["publicKey"]["authenticatorSelection"]["authenticatorAttachment"],
            "platform"
        );
        assert_eq!(
            options["publicKey"]["authenticatorSelection"]["userVerification"],
            "required"
        );
    }

    #[test]
    fn passkey_approval_is_action_bound_and_single_use() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passkeys.json");
        let webauthn = webauthn().unwrap();
        let user_id = Uuid::new_v4();
        let (options, registration) = webauthn
            .start_passkey_registration(user_id, "admin", "Admin", None)
            .unwrap();
        let origin = Url::parse(ORIGIN).unwrap();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let credential = authenticator
            .do_registration(origin.clone(), options)
            .unwrap();
        let passkey = webauthn
            .finish_passkey_registration(&credential, &registration)
            .unwrap();
        save_store(
            &path,
            &PasskeyStore {
                user_id,
                username: "admin".into(),
                passkeys: vec![passkey],
            },
        )
        .unwrap();

        let mut gate = AdminGate::load(&path).unwrap();
        let challenge = gate.begin("peers.revoke").unwrap();
        let challenge_id: Uuid = serde_json::from_value(challenge["challenge_id"].clone()).unwrap();
        let options: RequestChallengeResponse =
            serde_json::from_value(challenge["options"].clone()).unwrap();
        let credential = authenticator.do_authentication(origin, options).unwrap();
        let approval = AdminApproval {
            challenge_id,
            action: "peers.revoke".into(),
            credential,
        };
        assert!(gate.verify(approval.clone(), "peers.block").is_err());
        assert!(gate.verify(approval, "peers.revoke").is_err());

        let challenge = gate.begin("peers.revoke").unwrap();
        let challenge_id: Uuid = serde_json::from_value(challenge["challenge_id"].clone()).unwrap();
        let options: RequestChallengeResponse =
            serde_json::from_value(challenge["options"].clone()).unwrap();
        let credential = authenticator
            .do_authentication(Url::parse(ORIGIN).unwrap(), options)
            .unwrap();
        let approval = AdminApproval {
            challenge_id,
            action: "peers.revoke".into(),
            credential,
        };
        assert!(gate.verify(approval.clone(), "peers.revoke").is_ok());
        assert!(gate.verify(approval, "peers.revoke").is_err());

        assert!(gate.require_agent_session(SessionScope::Routine).is_err());
        let session = gate.open_agent_session(SessionScope::Routine, 5).unwrap();
        assert_eq!(session["unlocked"], true);
        assert!(gate.require_agent_session(SessionScope::Routine).is_ok());
        assert!(gate.require_agent_session(SessionScope::External).is_err());
        gate.routine_session.as_mut().unwrap().expires_at =
            Utc::now() - chrono::Duration::seconds(1);
        assert!(gate.require_agent_session(SessionScope::Routine).is_err());
        gate.open_agent_session(SessionScope::External, 5).unwrap();
        assert_eq!(gate.session_status()["external"]["unlocked"], true);
        gate.lock_agent_sessions();
        assert!(gate.require_agent_session(SessionScope::External).is_err());
    }
}
