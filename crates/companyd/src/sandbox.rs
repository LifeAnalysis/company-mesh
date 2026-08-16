use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
};

use serde_json::Value;
use tempfile::TempDir;
use thiserror::Error;
use tokio::process::Command;

use crate::delegation::ServiceDefinition;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("no supported operating-system process sandbox is installed")]
    Unavailable,
    #[error("credential provider failed: {0}")]
    CredentialProvider(String),
    #[error("failed to prepare temporary credential files: {0}")]
    CredentialIo(#[from] std::io::Error),
    #[error("invalid credential file name or environment variable")]
    InvalidCredentialTarget,
}

#[derive(Debug, Clone)]
pub struct CredentialRequest<'a> {
    pub service: &'a str,
    pub project: &'a str,
    pub operation: &'a str,
}

/// Providers broker credentials at execution time. Implementations must write only to
/// the supplied lease; paths are injected into the child environment and deleted when
/// the child exits. Credential contents never cross Iroh or enter the event log.
pub trait CredentialProvider: Send + Sync {
    fn materialize(
        &self,
        request: &CredentialRequest<'_>,
        lease: &mut CredentialLease,
    ) -> Result<(), SandboxError>;
}

#[derive(Debug, Default)]
pub struct NoCredentialProvider;

impl CredentialProvider for NoCredentialProvider {
    fn materialize(
        &self,
        _request: &CredentialRequest<'_>,
        _lease: &mut CredentialLease,
    ) -> Result<(), SandboxError> {
        Ok(())
    }
}

pub struct CredentialLease {
    directory: TempDir,
    environment: BTreeMap<String, PathBuf>,
}

impl CredentialLease {
    pub fn new() -> Result<Self, SandboxError> {
        let directory = tempfile::Builder::new()
            .prefix("company-mesh-credentials-")
            .tempdir()?;
        set_owner_only_directory(directory.path())?;
        Ok(Self {
            directory,
            environment: BTreeMap::new(),
        })
    }

    /// Write one brokered value into an owner-only temporary file. This type does not
    /// implement Debug, and callers must never log `contents` or place them in fixtures.
    pub fn write(
        &mut self,
        environment_variable: &str,
        file_name: &str,
        contents: &[u8],
    ) -> Result<PathBuf, SandboxError> {
        if !valid_environment_variable(environment_variable) || !valid_file_name(file_name) {
            return Err(SandboxError::InvalidCredentialTarget);
        }
        let path = self.directory.path().join(file_name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        file.write_all(contents)?;
        file.sync_all()?;
        self.environment
            .insert(environment_variable.to_owned(), path.clone());
        Ok(path)
    }

    pub fn path(&self) -> &Path {
        self.directory.path()
    }

    fn environment(&self) -> &BTreeMap<String, PathBuf> {
        &self.environment
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SandboxBackend {
    MacOs,
    LinuxBubblewrap,
}

impl SandboxBackend {
    fn detect() -> Result<Self, SandboxError> {
        if cfg!(target_os = "macos") && Path::new("/usr/bin/sandbox-exec").is_file() {
            Ok(Self::MacOs)
        } else if cfg!(target_os = "linux") && executable_on_path("bwrap") {
            Ok(Self::LinuxBubblewrap)
        } else {
            Err(SandboxError::Unavailable)
        }
    }
}

pub struct SandboxedCommand {
    pub command: Command,
    _credentials: CredentialLease,
}

pub fn prepare_command(
    definition: &ServiceDefinition,
    operation: &str,
    project: &str,
    parameters: &Value,
    provider: &dyn CredentialProvider,
) -> Result<SandboxedCommand, SandboxError> {
    let backend = SandboxBackend::detect()?;
    prepare_command_with_backend(
        definition, operation, project, parameters, provider, backend,
    )
}

fn prepare_command_with_backend(
    definition: &ServiceDefinition,
    operation: &str,
    project: &str,
    parameters: &Value,
    provider: &dyn CredentialProvider,
    backend: SandboxBackend,
) -> Result<SandboxedCommand, SandboxError> {
    let mut lease = CredentialLease::new()?;
    provider.materialize(
        &CredentialRequest {
            service: &definition.name,
            project,
            operation,
        },
        &mut lease,
    )?;
    let operation = definition
        .operations
        .get(operation)
        .ok_or_else(|| SandboxError::CredentialProvider("operation is not registered".into()))?;
    let arguments = operation
        .render(project, parameters)
        .map_err(|error| SandboxError::CredentialProvider(error.to_string()))?;
    let mut command = match backend {
        SandboxBackend::MacOs => macos_command(definition, &arguments, &mut lease)?,
        SandboxBackend::LinuxBubblewrap => linux_command(definition, &arguments, &lease),
    };
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", lease.path())
        .envs(lease.environment())
        .current_dir(lease.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    Ok(SandboxedCommand {
        command,
        _credentials: lease,
    })
}

fn macos_command(
    definition: &ServiceDefinition,
    arguments: &[String],
    lease: &mut CredentialLease,
) -> Result<Command, SandboxError> {
    let mut extra_reads = String::new();
    for path in &definition.read_only_paths {
        let filter = if Path::new(path).is_dir() {
            "subpath"
        } else {
            "literal"
        };
        extra_reads.push_str(&format!(
            "(allow file-read* ({filter} {}))\n",
            scheme_string(path)
        ));
    }
    let network_rule = if definition.allow_network {
        "(allow network*)"
    } else {
        "(deny network*)"
    };
    let profile = format!(
        r#"(version 1)
(deny default)
(allow process*)
(allow sysctl-read)
(allow mach-lookup)
(allow file-read* (literal "/") (subpath "/System") (subpath "/usr/lib") (subpath "/usr/share") (subpath "/Library/Apple") (subpath "/dev") (literal {} ) (subpath {}))
{}
(allow file-write* (subpath {}))
{}
"#,
        scheme_string(&definition.executable),
        scheme_string(&lease.path().to_string_lossy()),
        extra_reads,
        scheme_string(&lease.path().to_string_lossy()),
        network_rule,
    );
    let profile_path = lease.write(
        "COMPANY_MESH_SANDBOX_PROFILE",
        "sandbox.sb",
        profile.as_bytes(),
    )?;
    // The profile location is an implementation detail, not child authority.
    lease.environment.remove("COMPANY_MESH_SANDBOX_PROFILE");
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command
        .arg("-f")
        .arg(profile_path)
        .arg(&definition.executable)
        .args(arguments);
    Ok(command)
}

fn linux_command(
    definition: &ServiceDefinition,
    arguments: &[String],
    lease: &CredentialLease,
) -> Command {
    let mut command = Command::new("bwrap");
    command.args(["--die-with-parent", "--new-session", "--clearenv"]);
    if definition.allow_network {
        command.args([
            "--unshare-user",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-uts",
            "--unshare-cgroup",
        ]);
    } else {
        command.arg("--unshare-all");
    }
    command.args([
        "--ro-bind",
        "/usr",
        "/usr",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--ro-bind",
    ]);
    command
        .arg(lease.path())
        .arg(lease.path())
        .arg("--chdir")
        .arg(lease.path())
        .args(["--setenv", "PATH", "/usr/bin:/bin", "--setenv", "TMPDIR"])
        .arg(lease.path());
    for (name, path) in lease.environment() {
        command.arg("--setenv").arg(name).arg(path);
    }
    if Path::new("/bin").exists() {
        command.args(["--ro-bind", "/bin", "/bin"]);
    }
    if !definition.executable.starts_with("/usr/") && !definition.executable.starts_with("/bin/") {
        command
            .arg("--ro-bind")
            .arg(&definition.executable)
            .arg(&definition.executable);
    }
    for path in &definition.read_only_paths {
        command.arg("--ro-bind").arg(path).arg(path);
    }
    command
        .arg("--")
        .arg(&definition.executable)
        .args(arguments);
    command
}

fn executable_on_path(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|directory| directory.join(name).is_file())
    })
}

fn valid_environment_variable(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_file_name(value: &str) -> bool {
    !value.is_empty() && value != "." && value != ".." && !value.contains(['/', '\\'])
}

fn scheme_string(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a string cannot fail")
}

#[cfg(unix)]
fn set_owner_only_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_owner_only_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation::ServiceOperation;
    use std::os::unix::fs::PermissionsExt;

    fn definition() -> ServiceDefinition {
        ServiceDefinition {
            name: "source-index".to_owned(),
            executable: "/usr/bin/printf".to_owned(),
            executable_hash: "not-used-by-command-builder".to_owned(),
            operations: BTreeMap::from([(
                "inspect".to_owned(),
                ServiceOperation::Legacy(vec!["%s".to_owned(), "{project}".to_owned()]),
            )]),
            timeout_seconds: 1,
            max_output_bytes: 1024,
            allow_network: false,
            read_only_paths: Vec::new(),
            cedar_policy: String::new(),
        }
    }

    #[test]
    fn credential_lease_is_owner_only_and_removed_on_drop() {
        let directory;
        let file;
        {
            let mut lease = CredentialLease::new().unwrap();
            directory = lease.path().to_owned();
            file = lease
                .write("SERVICE_CREDENTIAL_FILE", "credential", b"")
                .unwrap();
            assert_eq!(
                std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(lease.environment()["SERVICE_CREDENTIAL_FILE"], file);
        }
        assert!(!directory.exists());
        assert!(!file.exists());
    }

    #[test]
    fn macos_sandbox_command_clears_environment_and_denies_network() {
        let prepared = prepare_command_with_backend(
            &definition(),
            "inspect",
            "mesh",
            &serde_json::json!({}),
            &NoCredentialProvider,
            SandboxBackend::MacOs,
        )
        .unwrap();
        let std_command = prepared.command.as_std();
        assert_eq!(std_command.get_program(), "/usr/bin/sandbox-exec");
        assert!(
            std_command
                .get_envs()
                .any(|(key, value)| key == "PATH" && value.is_some())
        );
        let environment = std_command
            .get_envs()
            .map(|(key, _)| key.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(environment, ["PATH", "TMPDIR"]);
        let profile =
            std::fs::read_to_string(prepared._credentials.path().join("sandbox.sb")).unwrap();
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(deny network*)"));
    }

    #[test]
    fn macos_sandbox_can_opt_in_to_network_and_read_paths() {
        let mut service = definition();
        service.allow_network = true;
        service.read_only_paths = vec!["/usr/share".to_owned(), "/usr/bin/printf".to_owned()];
        let prepared = prepare_command_with_backend(
            &service,
            "inspect",
            "mesh",
            &serde_json::json!({}),
            &NoCredentialProvider,
            SandboxBackend::MacOs,
        )
        .unwrap();
        let profile =
            std::fs::read_to_string(prepared._credentials.path().join("sandbox.sb")).unwrap();
        assert!(profile.contains("(allow network*)"));
        assert!(!profile.contains("(deny network*)"));
        assert!(profile.contains("(subpath \"/usr/share\")"));
        assert!(profile.contains("(literal \"/usr/bin/printf\")"));
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_sandbox_executes_a_registered_binary() {
        let mut prepared = prepare_command_with_backend(
            &definition(),
            "inspect",
            "mesh",
            &serde_json::json!({}),
            &NoCredentialProvider,
            SandboxBackend::MacOs,
        )
        .unwrap();
        let output = prepared.command.output().await.unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("mesh"));
    }

    #[test]
    fn linux_sandbox_keeps_network_isolated_by_default() {
        let lease = CredentialLease::new().unwrap();
        let command = linux_command(&definition(), &["mesh".to_owned()], &lease);
        let arguments = command
            .as_std()
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(arguments.iter().any(|argument| argument == "--unshare-all"));
    }

    #[test]
    fn linux_sandbox_can_keep_host_network_and_mount_read_paths() {
        let mut service = definition();
        service.allow_network = true;
        service.read_only_paths = vec!["/usr/share".to_owned()];
        let lease = CredentialLease::new().unwrap();
        let command = linux_command(&service, &["mesh".to_owned()], &lease);
        let arguments = command
            .as_std()
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(!arguments.iter().any(|argument| argument == "--unshare-all"));
        assert!(arguments.iter().any(|argument| argument == "--unshare-pid"));
        assert!(
            arguments
                .windows(3)
                .any(|window| { window == ["--ro-bind", "/usr/share", "/usr/share"] })
        );
    }
}
