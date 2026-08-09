//! Reading and writing the vault file.
//!
//! A vault is the only copy of the user's credentials. A save that is interrupted — power loss,
//! a full disk, the process being killed — must leave the previous vault intact rather than a
//! half-written file that opens for nobody. Every write therefore goes to a temporary file in
//! the same directory, is flushed to the platter, and only then replaces the real one by rename.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::vault::format::{decode, encode_with, SealingKey, VaultError};

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("there is no vault at this location")]
    NotFound,
    #[error("the vault file could not be read or written: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Format(#[from] VaultError),
}

/// Scratch path a save is staged through. Kept beside the vault because `rename` is only atomic
/// within a single filesystem, which a system temp directory does not guarantee.
fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

/// True when a vault already exists at `path`.
pub fn exists(path: &Path) -> bool {
    path.is_file()
}

/// Seals `body` with an already derived key and writes it atomically.
///
/// This is the path an unlocked session takes on every edit: no master password involved, and no
/// second Argon2 derivation.
pub fn save_sealed(
    path: &Path,
    sealing: &SealingKey,
    counter: u64,
    body: &[u8],
) -> Result<(), StorageError> {
    write_atomically(path, &encode_with(sealing, counter, body)?)?;
    // Written after the vault, not before. If the process dies in between, the recorded counter
    // is one behind reality, which reads as "nothing to report" — the safe direction. The other
    // order would accuse a perfectly good vault of being a rollback.
    write_highest_seen(path, counter);

    Ok(())
}

/// Where the highest save counter seen so far is recorded.
fn seen_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".seen");
    path.with_file_name(name)
}

/// Records the counter, best effort.
///
/// A failure here is not worth failing a save over: the vault itself is already written, and the
/// only consequence is that a later rollback goes unreported.
fn write_highest_seen(path: &Path, counter: u64) {
    // Only ever upwards. It is the *highest* counter seen, not the last one written: lowering it
    // would let a restored vault quietly erase the evidence that a newer one existed, and the
    // next rollback would go unreported.
    if highest_seen(path).is_some_and(|seen| seen >= counter) {
        return;
    }

    let _ = create_private(&seen_path(path))
        .and_then(|mut file| file.write_all(&counter.to_le_bytes()));
}

/// The highest save counter this installation has recorded, if any.
///
/// A missing or unreadable record answers `None` rather than zero. `None` means "no opinion", so
/// a first run — or a wiped record — reports nothing instead of accusing a valid vault.
pub fn highest_seen(path: &Path) -> Option<u64> {
    let bytes = fs::read(seen_path(path)).ok()?;

    Some(u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?))
}

/// Reads the raw bytes of a vault, for a caller that will derive its own key from the header.
pub fn read_sealed(path: &Path) -> Result<Vec<u8>, StorageError> {
    fs::read(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => StorageError::NotFound,
        _ => StorageError::Io(error),
    })
}

/// Reads and unseals the vault at `path`.
pub fn load(path: &Path, password: &[u8]) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    Ok(decode(password, &read_sealed(path)?)?)
}

fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temp = temp_path(path);

    // A previous run may have died between creating the temp file and renaming it, so truncate
    // rather than trusting whatever is there.
    let result = (|| {
        let mut file = create_private(&temp)?;
        file.write_all(bytes)?;
        // Without this, the rename can land before the contents do, and a crash in between
        // leaves a vault that is present, correctly named, and empty.
        file.sync_all()?;
        drop(file);

        fs::rename(&temp, path)?;
        sync_parent_directory(path)
    })();

    if result.is_err() {
        // Best effort: the save already failed, and a leftover temp file would be overwritten by
        // the next attempt anyway.
        let _ = fs::remove_file(&temp);
    }

    result
}

#[cfg(unix)]
fn create_private(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    // 0600 at creation time, not afterwards: setting the mode after the file exists leaves a
    // window in which another user on the machine can open it.
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private(path: &Path) -> std::io::Result<File> {
    // Windows has no mode bits. The file inherits the directory's ACL, which for a per-user
    // application data directory is already restricted to the owner.
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> std::io::Result<()> {
    // The rename is a directory operation; flushing the file does not make it durable.
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> std::io::Result<()> {
    // Directories cannot be opened as files on Windows; `ReplaceFile` semantics cover this.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    use crate::crypto::kdf::KdfParams;
    use crate::vault::format::FIRST_SAVE;

    const PASSWORD: &[u8] = b"correct horse battery staple";
    const BODY: &[u8] = b"[{\"site\":\"github.com\"}]";

    fn cheap() -> KdfParams {
        KdfParams::new(8, 1, 1).expect("cheap test parameters must be valid")
    }

    fn vault_in(dir: &TempDir) -> PathBuf {
        dir.path().join("vault.pwm")
    }

    /// Writes through the same path the application uses. There is no password-based `save`:
    /// it would write a vault to disk without recording its counter, quietly defeating the
    /// rollback check for anyone who reached for it.
    fn save_body(path: &Path, counter: u64, body: &[u8]) {
        let sealing = SealingKey::create(PASSWORD, cheap()).expect("a sealing key");
        save_sealed(path, &sealing, counter, body).unwrap();
    }

    #[test]
    fn saves_and_loads_a_body() {
        let dir = TempDir::new().unwrap();
        let path = vault_in(&dir);

        save_body(&path, FIRST_SAVE, BODY);

        assert_eq!(load(&path, PASSWORD).unwrap().as_slice(), BODY);
    }

    #[test]
    fn overwrites_an_existing_vault() {
        let dir = TempDir::new().unwrap();
        let path = vault_in(&dir);

        save_body(&path, FIRST_SAVE, BODY);
        save_body(&path, FIRST_SAVE + 1, b"replaced");

        assert_eq!(load(&path, PASSWORD).unwrap().as_slice(), b"replaced");
    }

    #[test]
    fn leaves_no_temporary_file_behind() {
        let dir = TempDir::new().unwrap();
        let path = vault_in(&dir);

        save_body(&path, FIRST_SAVE, BODY);

        let mut entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        entries.sort();

        // The vault and the counter record. Anything else is a staging file that outlived its
        // save.
        assert_eq!(entries, vec!["vault.pwm", "vault.pwm.seen"]);
    }

    #[test]
    fn records_the_counter_it_wrote() {
        let dir = TempDir::new().unwrap();
        let path = vault_in(&dir);

        save_body(&path, 7, BODY);

        assert_eq!(highest_seen(&path), Some(7));
    }

    #[test]
    fn never_lowers_the_record() {
        let dir = TempDir::new().unwrap();
        let path = vault_in(&dir);

        save_body(&path, 9, BODY);
        save_body(&path, 4, BODY);

        // A restored vault saving at a lower counter must not erase the evidence that a newer
        // one existed, or the next rollback goes unreported.
        assert_eq!(highest_seen(&path), Some(9));
    }

    #[test]
    fn has_no_opinion_before_anything_has_been_saved() {
        let dir = TempDir::new().unwrap();

        // `None` means "no opinion", not zero. A first run must not accuse a valid vault.
        assert_eq!(highest_seen(&vault_in(&dir)), None);
    }

    #[test]
    fn has_no_opinion_when_the_record_is_unreadable() {
        let dir = TempDir::new().unwrap();
        let path = vault_in(&dir);
        save_body(&path, 7, BODY);
        std::fs::write(seen_path(&path), b"junk").unwrap();

        // Truncated or corrupt reads as absent rather than as zero, for the same reason.
        assert_eq!(highest_seen(&path), None);
    }

    #[test]
    fn keeps_the_record_readable_only_by_its_owner() {
        let dir = TempDir::new().unwrap();
        let path = vault_in(&dir);

        save_body(&path, FIRST_SAVE, BODY);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(seen_path(&path))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn a_stale_temporary_file_does_not_break_a_save() {
        let dir = TempDir::new().unwrap();
        let path = vault_in(&dir);
        // What a crash mid-write would leave behind.
        std::fs::write(temp_path(&path), b"garbage from a crashed write").unwrap();

        save_body(&path, FIRST_SAVE, BODY);

        assert_eq!(load(&path, PASSWORD).unwrap().as_slice(), BODY);
    }

    #[test]
    fn rejects_a_wrong_password() {
        let dir = TempDir::new().unwrap();
        let path = vault_in(&dir);
        save_body(&path, FIRST_SAVE, BODY);

        let error = load(&path, b"wrong").unwrap_err();

        assert!(matches!(
            error,
            StorageError::Format(VaultError::Unauthentic)
        ));
    }

    #[test]
    fn reports_a_missing_vault_distinctly() {
        let dir = TempDir::new().unwrap();

        let error = load(&vault_in(&dir), PASSWORD).unwrap_err();

        // The caller needs to tell "no vault yet, offer to create one" apart from "something
        // went wrong", and that distinction leaks nothing.
        assert!(matches!(error, StorageError::NotFound));
    }

    #[test]
    fn rejects_a_file_that_is_not_a_vault() {
        let dir = TempDir::new().unwrap();
        let path = vault_in(&dir);
        std::fs::write(&path, b"this is not a vault, it is a shopping list").unwrap();

        let error = load(&path, PASSWORD).unwrap_err();

        assert!(matches!(error, StorageError::Format(VaultError::NotAVault)));
    }

    #[test]
    fn reports_whether_a_vault_exists() {
        let dir = TempDir::new().unwrap();
        let path = vault_in(&dir);

        assert!(!exists(&path));
        save_body(&path, FIRST_SAVE, BODY);
        assert!(exists(&path));
    }

    #[test]
    fn fails_when_the_directory_does_not_exist() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nope").join("vault.pwm");

        assert!(save_sealed(
            &path,
            &SealingKey::create(PASSWORD, cheap()).unwrap(),
            FIRST_SAVE,
            BODY
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn creates_the_vault_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = vault_in(&dir);

        save_body(&path, FIRST_SAVE, BODY);

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();

        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn tightens_permissions_on_an_existing_world_readable_vault() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = vault_in(&dir);
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        save_body(&path, FIRST_SAVE, BODY);

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();

        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn a_save_that_cannot_complete_leaves_the_existing_vault_intact() {
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = vault_in(&dir);
        save_body(&path, FIRST_SAVE, BODY);

        // Staging through a temp file needs to create one, so a directory that forbids creation
        // stops the save before the real vault is touched. Writing straight to the vault would
        // only need permission on the file itself, and would destroy it.
        std::fs::set_permissions(dir.path(), Permissions::from_mode(0o500)).unwrap();
        // Root ignores the mode bits, and then this test proves nothing. Probe for that with an
        // operation that is not the one under test, so a save that wrongly succeeds cannot be
        // mistaken for running as root.
        let running_as_root = File::create(dir.path().join("probe")).is_ok();
        let blocked = std::panic::catch_unwind(|| save_body(&path, FIRST_SAVE + 1, b"replacement"));
        std::fs::set_permissions(dir.path(), Permissions::from_mode(0o700)).unwrap();

        if running_as_root {
            return;
        }

        assert!(blocked.is_err(), "the save must not have been possible");
        assert_eq!(load(&path, PASSWORD).unwrap().as_slice(), BODY);
    }

    #[test]
    fn error_messages_do_not_mention_secrets() {
        // The `Io` variant is excluded on purpose: it carries a path, and a path is chosen by
        // the user, not by this code.
        for error in [
            StorageError::NotFound,
            StorageError::Format(VaultError::Unauthentic),
        ] {
            let message = error.to_string().to_lowercase();

            assert!(!message.is_empty());
            assert!(!message.contains("plaintext"));
        }
    }
}
