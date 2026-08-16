use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

pub fn default_data_dir() -> Result<PathBuf> {
    dirs::data_local_dir()
        .map(|path| path.join("company-mesh"))
        .context("cannot determine the local data directory")
}

pub fn install(data_dir: &Path, companyd: &Path) -> Result<PathBuf> {
    if !companyd.is_absolute() || !data_dir.is_absolute() {
        bail!("service paths must be absolute");
    }
    #[cfg(target_os = "macos")]
    {
        let home = dirs::home_dir().context("cannot determine the home directory")?;
        let path = home
            .join("Library")
            .join("LaunchAgents")
            .join("com.companymesh.daemon.plist");
        std::fs::create_dir_all(path.parent().context("invalid LaunchAgents path")?)?;
        let content = render_launchd(data_dir, companyd);
        write_owner_file(&path, content.as_bytes())?;
        let uid = std::process::Command::new("id").arg("-u").output()?;
        if !uid.status.success() {
            bail!("cannot determine the current user ID");
        }
        let domain = format!("gui/{}", String::from_utf8(uid.stdout)?.trim());
        let _ = std::process::Command::new("launchctl")
            .args(["bootout", &domain])
            .arg(&path)
            .status();
        let status = std::process::Command::new("launchctl")
            .args(["bootstrap", &domain])
            .arg(&path)
            .status()?;
        if !status.success() {
            bail!("launchctl could not start Company Mesh");
        }
        Ok(path)
    }
    #[cfg(target_os = "linux")]
    {
        let config = dirs::config_dir().context("cannot determine the config directory")?;
        let path = config.join("systemd/user/company-mesh.service");
        std::fs::create_dir_all(path.parent().context("invalid systemd path")?)?;
        write_owner_file(&path, render_systemd(data_dir, companyd).as_bytes())?;
        for args in [
            ["--user", "daemon-reload"].as_slice(),
            ["--user", "enable", "--now", "company-mesh.service"].as_slice(),
        ] {
            let status = std::process::Command::new("systemctl")
                .args(args)
                .status()?;
            if !status.success() {
                bail!("systemctl could not install Company Mesh");
            }
        }
        Ok(path)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        bail!("automatic service installation supports macOS and Linux only")
    }
}

pub fn uninstall() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let path = dirs::home_dir()
            .context("cannot determine the home directory")?
            .join("Library/LaunchAgents/com.companymesh.daemon.plist");
        let uid = std::process::Command::new("id").arg("-u").output()?;
        let domain = format!("gui/{}", String::from_utf8(uid.stdout)?.trim());
        let _ = std::process::Command::new("launchctl")
            .args(["bootout", &domain])
            .arg(&path)
            .status();
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", "--now", "company-mesh.service"])
            .status();
        let path = dirs::config_dir()
            .context("cannot determine the config directory")?
            .join("systemd/user/company-mesh.service");
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        bail!("automatic service removal supports macOS and Linux only")
    }
}

pub fn render_launchd(data_dir: &Path, companyd: &Path) -> String {
    let binary = xml_escape(&companyd.display().to_string());
    let data = xml_escape(&data_dir.display().to_string());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.companymesh.daemon</string>
<key>ProgramArguments</key><array><string>{binary}</string><string>--data-dir</string><string>{data}</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>{data}/companyd.stdout.log</string>
<key>StandardErrorPath</key><string>{data}/companyd.stderr.log</string>
</dict></plist>
"#
    )
}

pub fn render_systemd(data_dir: &Path, companyd: &Path) -> String {
    format!(
        "[Unit]\nDescription=Company Mesh agent daemon\nAfter=network-online.target\n\n[Service]\nExecStart=\"{}\" --data-dir \"{}\"\nRestart=on-failure\nRestartSec=5\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths=\"{}\"\n\n[Install]\nWantedBy=default.target\n",
        systemd_escape(companyd),
        systemd_escape(data_dir),
        systemd_escape(data_dir),
    )
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn systemd_escape(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(['\n', '\r'], "")
}

fn write_owner_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::{fs::OpenOptions, io::Write};
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
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_files_escape_paths() {
        let launchd = render_launchd(Path::new("/tmp/a&b"), Path::new("/bin/companyd"));
        assert!(launchd.contains("a&amp;b"));
        let systemd = render_systemd(Path::new("/tmp/a b"), Path::new("/bin/companyd"));
        assert!(systemd.contains("ReadWritePaths=\"/tmp/a b\""));
    }
}
