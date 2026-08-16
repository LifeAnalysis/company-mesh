use std::process::Stdio;

use anyhow::Result;
use tokio::process::Command;

pub async fn inbound_message(enabled: bool, peer: &str, scope: &str) -> Result<()> {
    if !enabled {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        let text = format!("New Company Mesh message from {peer} in {scope}");
        let script = format!(
            "display notification {} with title {}",
            apple_script_string(&text),
            apple_script_string("Company Mesh")
        );
        let _ = Command::new("osascript")
            .args(["-e", &script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
    }
    #[cfg(target_os = "linux")]
    {
        let text = format!("New message from {peer} in {scope}");
        let _ = Command::new("notify-send")
            .args(["Company Mesh", &text])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn apple_script_string(value: &str) -> String {
    format!("{:?}", value)
}
