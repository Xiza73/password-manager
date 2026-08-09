//! End-to-end exercise of every layer through the public API only.
//!
//! The unit tests each cover one module. This covers the seam between them: credentials become
//! bytes, bytes become a sealed file, the file survives a trip through the filesystem, and what
//! comes back is what went in.

use password_manager_lib::crypto::kdf::KdfParams;
use password_manager_lib::secret::SecretString;
use password_manager_lib::vault::entries::{CredentialDraft, VaultData};
use password_manager_lib::vault::format::VaultError;
use password_manager_lib::vault::storage::{load, save, StorageError};
use tempfile::TempDir;

const PASSWORD: &[u8] = b"correct horse battery staple";

/// Real parameters would make this test cost a second of Argon2 per unlock for no added
/// coverage; the cost itself is covered in the kdf module.
fn cheap() -> KdfParams {
    KdfParams::new(8, 1, 1).expect("cheap test parameters must be valid")
}

fn draft(site: &str, username: &str, password: &str) -> CredentialDraft {
    CredentialDraft {
        site: site.to_owned(),
        username: username.to_owned(),
        password: SecretString::new(password.to_owned()),
        notes: SecretString::new(String::new()),
    }
}

#[test]
fn credentials_survive_a_full_save_and_load() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.pwm");

    let mut data = VaultData::new();
    let github = data.add(draft("github.com", "octocat", "hunter2")).unwrap();
    data.add(draft("gitlab.com", "tanuki", "correct-horse"))
        .unwrap();

    save(&path, PASSWORD, &data.to_bytes().unwrap(), cheap()).unwrap();
    let restored = VaultData::from_bytes(&load(&path, PASSWORD).unwrap()).unwrap();

    assert_eq!(restored, data);
    assert_eq!(restored.get(github).unwrap().password().expose(), "hunter2");
}

#[test]
fn an_edit_replaces_what_is_on_disk() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.pwm");

    let mut data = VaultData::new();
    let id = data.add(draft("github.com", "octocat", "hunter2")).unwrap();
    save(&path, PASSWORD, &data.to_bytes().unwrap(), cheap()).unwrap();

    data.update(id, draft("github.com", "octocat", "rotated"))
        .unwrap();
    save(&path, PASSWORD, &data.to_bytes().unwrap(), cheap()).unwrap();

    let restored = VaultData::from_bytes(&load(&path, PASSWORD).unwrap()).unwrap();
    assert_eq!(restored.get(id).unwrap().password().expose(), "rotated");
    assert_eq!(restored.summaries().len(), 1);
}

#[test]
fn a_wrong_master_password_yields_nothing() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.pwm");

    let mut data = VaultData::new();
    data.add(draft("github.com", "octocat", "hunter2")).unwrap();
    save(&path, PASSWORD, &data.to_bytes().unwrap(), cheap()).unwrap();

    let error = load(&path, b"almost the right password").unwrap_err();

    assert!(matches!(
        error,
        StorageError::Format(VaultError::Unauthentic)
    ));
}

#[test]
fn the_vault_file_never_holds_a_password_in_the_clear() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.pwm");

    let mut data = VaultData::new();
    data.add(draft("github.com", "octocat", "hunter2")).unwrap();
    save(&path, PASSWORD, &data.to_bytes().unwrap(), cheap()).unwrap();

    let raw = std::fs::read(&path).unwrap();

    for secret in [b"hunter2".as_slice(), b"octocat".as_slice(), b"github.com"] {
        assert!(
            !raw.windows(secret.len()).any(|window| window == secret),
            "the vault file leaked {}",
            String::from_utf8_lossy(secret)
        );
    }
}
