use std::{fs::OpenOptions, io::Write, path::Path};

use anyhow::{Context, Result};
use iroh::SecretKey;

pub fn load_or_create_secret(path: &Path) -> Result<SecretKey> {
    if path.exists() {
        let encoded = std::fs::read_to_string(path)
            .with_context(|| format!("read identity key {}", path.display()))?;
        let bytes = hex::decode(encoded.trim()).context("decode identity key")?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("identity key has invalid length"))?;
        return Ok(SecretKey::from_bytes(&bytes));
    }
    let secret = SecretKey::generate();
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?
    };
    #[cfg(not(unix))]
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(hex::encode(secret.to_bytes()).as_bytes())?;
    file.sync_all()?;
    Ok(secret)
}
