use std::fs;

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

    fs::write(&private_key_path, private_key)?;
    let auth_result = session.userauth_pubkey_file(username, None, &private_key_path, None);

    if let Err(err) = fs::remove_file(&private_key_path) {
        tracing::warn!(
            path = %private_key_path.display(),
            error = %err,
            "failed to remove temporary ssh key file"
        );
    }

    auth_result?;
    Ok(())
}
