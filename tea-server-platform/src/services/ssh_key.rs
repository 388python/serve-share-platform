use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use uuid::Uuid;

pub fn userauth_pubkey_from_memory(
    session: &ssh2::Session,
    username: &str,
    private_key: &str,
) -> anyhow::Result<()> {
    let private_key_path = std::env::temp_dir().join(format!(
        "tea-server-platform-ssh-key-{}.pem",
        Uuid::new_v4()
    ));

    write_private_key_file(&private_key_path, private_key)?;
    let auth_result = session.userauth_pubkey_file(username, None, &private_key_path, None);

    remove_private_key_file(&private_key_path);

    auth_result?;
    Ok(())
}

fn remove_private_key_file(path: &Path) {
    if let Err(err) = fs::remove_file(path) {
        tracing::warn!(
            path = %path.display(),
            error = %err,
            "failed to remove temporary ssh key file"
        );
    }
}

fn write_private_key_file(path: &Path, private_key: &str) -> anyhow::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    options.mode(0o600);

    let mut key_file = options.open(path)?;
    let write_result = key_file.write_all(private_key.as_bytes());
    drop(key_file);

    if let Err(err) = write_result {
        remove_private_key_file(path);
        return Err(err.into());
    }

    Ok(())
}
