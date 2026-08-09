//! The unlocked-vault state machine.
//!
//! Everything the application actually does lives here, deliberately free of Tauri: the command
//! layer above is a set of adapters thin enough to have nothing worth testing, and this is
//! testable without standing up a window.
//!
//! Two rules shape it. The master password is never kept — only the key derived from it, which
//! is strictly less to lose if the process memory is ever read. And every edit is written to disk
//! before it returns, so there is no unsaved state for a crash to take.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::crypto::kdf::KdfParams;
use crate::secret::SecretString;
use crate::vault::entries::{
    Credential, CredentialDraft, CredentialSummary, EntryError, EntryId, VaultData,
};
use crate::vault::format::{decode_with, SealingKey, VaultError};
use crate::vault::storage::{exists, read_sealed, save_sealed, StorageError};

/// Shortest master password this application will accept, in characters.
///
/// There are no character-class rules to go with it, and that is on purpose: demanding a digit
/// and a symbol is what produces `Passw0rd!`. Length is the only requirement that reliably buys
/// entropy, so it is the only one imposed. Twelve is a floor, not advice — a passphrase of four
/// unrelated words beats it comfortably.
pub const MIN_MASTER_PASSWORD_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("the vault is locked")]
    Locked,
    #[error("there is no vault yet")]
    NoVault,
    #[error("a vault already exists at this location")]
    VaultAlreadyExists,
    #[error("the master password must be at least {minimum} characters")]
    WeakMasterPassword { minimum: usize },
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error(transparent)]
    Entry(#[from] EntryError),
    #[error(transparent)]
    Storage(#[from] StorageError),
}

/// A credential with its secrets, returned only when one entry is asked for by name.
///
/// Listing hands back [`CredentialSummary`], which has no password field at all. This type is
/// the deliberate exception, and it exists so the interface can hold exactly one secret at a
/// time instead of all of them.
#[derive(Debug, Serialize)]
pub struct RevealedCredential {
    pub id: EntryId,
    pub site: String,
    pub username: String,
    pub password: SecretString,
    pub notes: SecretString,
}

impl RevealedCredential {
    fn of(credential: &Credential) -> Self {
        Self {
            id: credential.id(),
            site: credential.site().to_owned(),
            username: credential.username().to_owned(),
            password: credential.password().clone(),
            notes: credential.notes().clone(),
        }
    }
}

struct Open {
    sealing: SealingKey,
    data: VaultData,
    last_seen: Instant,
}

enum State {
    Locked,
    Open(Open),
}

pub struct Session {
    path: PathBuf,
    idle_timeout: Duration,
    params: KdfParams,
    state: State,
}

impl Session {
    pub fn new(path: PathBuf, idle_timeout: Duration, params: KdfParams) -> Self {
        Self {
            path,
            idle_timeout,
            params,
            state: State::Locked,
        }
    }

    pub fn vault_exists(&self) -> bool {
        exists(&self.path)
    }

    pub fn is_unlocked(&self) -> bool {
        matches!(self.state, State::Open(_))
    }

    /// Creates a new, empty vault and leaves it open.
    pub fn create(&mut self, password: &SecretString, now: Instant) -> Result<(), SessionError> {
        if self.vault_exists() {
            // Sealing a fresh vault over an existing one would destroy every credential in it,
            // and nothing about that is recoverable.
            return Err(SessionError::VaultAlreadyExists);
        }

        check_master_password(password)?;

        let sealing = SealingKey::create(password.expose().as_bytes(), self.params)?;
        let data = VaultData::new();
        save_sealed(&self.path, &sealing, &data.to_bytes()?)?;

        self.state = State::Open(Open {
            sealing,
            data,
            last_seen: now,
        });

        Ok(())
    }

    /// Opens an existing vault.
    pub fn unlock(&mut self, password: &SecretString, now: Instant) -> Result<(), SessionError> {
        // Read first, so a missing vault is reported as such rather than as a failed unlock.
        let file = match read_sealed(&self.path) {
            Ok(file) => file,
            Err(StorageError::NotFound) => return Err(SessionError::NoVault),
            Err(error) => return Err(error.into()),
        };

        // No length check on the way in. The rule applies to passwords this application chooses
        // to accept, not to vaults it has already sealed; raising the minimum must never lock
        // someone out of their own credentials.
        let sealing = SealingKey::from_file(password.expose().as_bytes(), &file)?;
        let data = VaultData::from_bytes(&decode_with(&sealing, &file)?)?;

        self.state = State::Open(Open {
            sealing,
            data,
            last_seen: now,
        });

        Ok(())
    }

    /// Closes the vault, dropping the key and the decrypted contents.
    pub fn lock(&mut self) {
        // Replacing the state drops `Open`, and with it the `SealingKey` and every
        // `SecretString` inside `VaultData` — each of which wipes itself.
        self.state = State::Locked;
    }

    /// Locks the vault if it has been idle past the timeout. Returns whether it just locked.
    pub fn lock_if_idle(&mut self, now: Instant) -> bool {
        let idle = match &self.state {
            State::Locked => false,
            State::Open(open) => now.duration_since(open.last_seen) >= self.idle_timeout,
        };

        if idle {
            self.lock();
        }

        idle
    }

    pub fn list(
        &mut self,
        query: &str,
        now: Instant,
    ) -> Result<Vec<CredentialSummary>, SessionError> {
        Ok(self.active(now)?.data.search(query))
    }

    pub fn reveal(
        &mut self,
        id: EntryId,
        now: Instant,
    ) -> Result<RevealedCredential, SessionError> {
        Ok(RevealedCredential::of(self.active(now)?.data.get(id)?))
    }

    pub fn add(&mut self, draft: CredentialDraft, now: Instant) -> Result<EntryId, SessionError> {
        let id = self.active(now)?.data.add(draft)?;
        self.persist()?;

        Ok(id)
    }

    pub fn update(
        &mut self,
        id: EntryId,
        draft: CredentialDraft,
        now: Instant,
    ) -> Result<(), SessionError> {
        self.active(now)?.data.update(id, draft)?;

        self.persist()
    }

    pub fn remove(&mut self, id: EntryId, now: Instant) -> Result<(), SessionError> {
        self.active(now)?.data.remove(id)?;

        self.persist()
    }

    /// Writes the open vault to disk, and repairs the in-memory copy if that fails.
    ///
    /// A failed write leaves memory holding an edit the disk never received. The disk is what
    /// the user gets back, so the interface must not go on showing a credential that was never
    /// saved: re-read instead. If even that fails there is nothing trustworthy left to show, and
    /// closing the vault is the only honest answer.
    fn persist(&mut self) -> Result<(), SessionError> {
        let result = match &self.state {
            State::Locked => return Err(SessionError::Locked),
            State::Open(open) => {
                open.data
                    .to_bytes()
                    .map_err(SessionError::from)
                    .and_then(|body| {
                        save_sealed(&self.path, &open.sealing, &body).map_err(SessionError::from)
                    })
            }
        };

        if result.is_err() && self.reload().is_err() {
            self.lock();
        }

        result
    }

    /// Replaces the in-memory contents with what is actually on disk, reusing the session key.
    fn reload(&mut self) -> Result<(), SessionError> {
        let file = read_sealed(&self.path)?;

        let State::Open(open) = &mut self.state else {
            return Err(SessionError::Locked);
        };

        open.data = VaultData::from_bytes(&decode_with(&open.sealing, &file)?)?;

        Ok(())
    }

    /// Checks the vault is open and not stale, and records the activity.
    ///
    /// The idle check lives here rather than only in the background timer, so a timer that never
    /// runs — a suspended process, a stalled thread — cannot leave the vault open forever.
    fn active(&mut self, now: Instant) -> Result<&mut Open, SessionError> {
        self.lock_if_idle(now);

        match &mut self.state {
            State::Locked => Err(SessionError::Locked),
            State::Open(open) => {
                open.last_seen = now;
                Ok(open)
            }
        }
    }
}

fn check_master_password(password: &SecretString) -> Result<(), SessionError> {
    // Characters, not bytes: counting bytes would quietly demand fewer letters of someone
    // writing in Latin script and more of someone writing in Cyrillic or Japanese.
    if password.expose().chars().count() < MIN_MASTER_PASSWORD_LEN {
        return Err(SessionError::WeakMasterPassword {
            minimum: MIN_MASTER_PASSWORD_LEN,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    const MASTER: &str = "a long enough master password";
    const TIMEOUT: Duration = Duration::from_secs(300);

    fn secret(value: &str) -> SecretString {
        SecretString::new(value.to_owned())
    }

    fn draft(site: &str, username: &str, password: &str) -> CredentialDraft {
        CredentialDraft {
            site: site.to_owned(),
            username: username.to_owned(),
            password: secret(password),
            notes: secret(""),
        }
    }

    /// Real Argon2 cost would add a fifth of a second to every single one of these tests.
    fn session_in(dir: &TempDir) -> Session {
        Session::new(
            dir.path().join("vault.pwm"),
            TIMEOUT,
            KdfParams::new(8, 1, 1).expect("cheap test parameters must be valid"),
        )
    }

    fn unlocked(dir: &TempDir, now: Instant) -> Session {
        let mut session = session_in(dir);
        session.create(&secret(MASTER), now).unwrap();
        session
    }

    #[test]
    fn starts_locked_and_empty() {
        let dir = TempDir::new().unwrap();
        let session = session_in(&dir);

        assert!(!session.is_unlocked());
        assert!(!session.vault_exists());
    }

    #[test]
    fn creating_a_vault_writes_it_and_leaves_it_open() {
        let dir = TempDir::new().unwrap();
        let mut session = session_in(&dir);

        session.create(&secret(MASTER), Instant::now()).unwrap();

        assert!(session.vault_exists());
        assert!(session.is_unlocked());
    }

    #[test]
    fn refuses_to_create_a_second_vault() {
        let dir = TempDir::new().unwrap();
        let mut session = unlocked(&dir, Instant::now());

        let result = session.create(&secret(MASTER), Instant::now());

        // Creating over an existing vault would destroy every credential in it.
        assert!(matches!(result, Err(SessionError::VaultAlreadyExists)));
    }

    #[test]
    fn refuses_a_short_master_password() {
        let dir = TempDir::new().unwrap();
        let mut session = session_in(&dir);

        let result = session.create(&secret("short"), Instant::now());

        assert!(matches!(
            result,
            Err(SessionError::WeakMasterPassword { minimum })
                if minimum == MIN_MASTER_PASSWORD_LEN
        ));
        assert!(!session.vault_exists());
    }

    #[test]
    fn measures_the_master_password_in_characters() {
        let dir = TempDir::new().unwrap();
        let mut session = session_in(&dir);

        // Twelve characters, more than twelve bytes. Counting bytes would accept a shorter
        // password in some scripts and reject a valid one in others.
        assert!(session
            .create(&secret("contraseñaña"), Instant::now())
            .is_ok());
    }

    #[test]
    fn unlocks_with_the_right_password() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        unlocked(&dir, now);

        let mut session = session_in(&dir);
        session.unlock(&secret(MASTER), now).unwrap();

        assert!(session.is_unlocked());
    }

    #[test]
    fn refuses_the_wrong_password_and_stays_locked() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        unlocked(&dir, now);

        let mut session = session_in(&dir);
        let result = session.unlock(&secret("a different long password"), now);

        assert!(matches!(
            result,
            Err(SessionError::Vault(VaultError::Unauthentic))
        ));
        assert!(!session.is_unlocked());
    }

    #[test]
    fn reports_that_there_is_no_vault_to_unlock() {
        let dir = TempDir::new().unwrap();
        let mut session = session_in(&dir);

        let result = session.unlock(&secret(MASTER), Instant::now());

        assert!(matches!(result, Err(SessionError::NoVault)));
    }

    #[test]
    fn locking_closes_the_vault() {
        let dir = TempDir::new().unwrap();
        let mut session = unlocked(&dir, Instant::now());

        session.lock();

        assert!(!session.is_unlocked());
        assert!(session.vault_exists());
    }

    #[test]
    fn every_operation_refuses_while_locked() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let mut session = unlocked(&dir, now);
        let id = session.add(draft("a.com", "u", "p"), now).unwrap();
        session.lock();

        assert!(matches!(session.list("", now), Err(SessionError::Locked)));
        assert!(matches!(session.reveal(id, now), Err(SessionError::Locked)));
        assert!(matches!(
            session.add(draft("b.com", "u", "p"), now),
            Err(SessionError::Locked)
        ));
        assert!(matches!(
            session.update(id, draft("b.com", "u", "p"), now),
            Err(SessionError::Locked)
        ));
        assert!(matches!(session.remove(id, now), Err(SessionError::Locked)));
    }

    #[test]
    fn an_added_credential_survives_a_lock_and_unlock() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let mut session = unlocked(&dir, now);

        let id = session
            .add(draft("github.com", "octocat", "hunter2"), now)
            .unwrap();
        session.lock();
        session.unlock(&secret(MASTER), now).unwrap();

        assert_eq!(
            session.reveal(id, now).unwrap().password.expose(),
            "hunter2"
        );
    }

    #[test]
    fn an_edit_is_written_through_immediately() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let mut session = unlocked(&dir, now);
        let id = session
            .add(draft("github.com", "octocat", "hunter2"), now)
            .unwrap();

        session
            .update(id, draft("github.com", "octocat", "rotated"), now)
            .unwrap();

        // A separate session sees it, so it reached the disk rather than sitting in memory
        // waiting for a save that a crash would lose.
        let mut other = session_in(&dir);
        other.unlock(&secret(MASTER), now).unwrap();
        assert_eq!(other.reveal(id, now).unwrap().password.expose(), "rotated");
    }

    #[test]
    fn a_removal_is_written_through_immediately() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let mut session = unlocked(&dir, now);
        let id = session.add(draft("a.com", "u", "p"), now).unwrap();

        session.remove(id, now).unwrap();

        let mut other = session_in(&dir);
        other.unlock(&secret(MASTER), now).unwrap();
        assert!(other.list("", now).unwrap().is_empty());
    }

    #[test]
    fn lists_and_filters_credentials() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let mut session = unlocked(&dir, now);
        session
            .add(draft("github.com", "octocat", "p"), now)
            .unwrap();
        session
            .add(draft("gitlab.com", "tanuki", "p"), now)
            .unwrap();

        assert_eq!(session.list("", now).unwrap().len(), 2);
        assert_eq!(session.list("lab", now).unwrap().len(), 1);
    }

    #[test]
    fn reports_an_unknown_credential() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let mut session = unlocked(&dir, now);

        let result = session.reveal(EntryId::new(), now);

        assert!(matches!(
            result,
            Err(SessionError::Entry(EntryError::NotFound))
        ));
    }

    #[test]
    fn locks_itself_once_the_idle_timeout_passes() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let mut session = unlocked(&dir, now);

        let locked = session.lock_if_idle(now + TIMEOUT + Duration::from_secs(1));

        assert!(locked);
        assert!(!session.is_unlocked());
    }

    #[test]
    fn stays_open_while_it_is_being_used() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let mut session = unlocked(&dir, now);

        // Each call is inside the window measured from the previous one, so the total elapsed
        // time is well past the timeout without the session ever going idle.
        let mut moment = now;
        for _ in 0..5 {
            moment += TIMEOUT - Duration::from_secs(1);
            session.list("", moment).unwrap();
        }

        assert!(session.is_unlocked());
        assert!(!session.lock_if_idle(moment));
    }

    #[test]
    fn an_idle_session_refuses_the_next_operation() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let mut session = unlocked(&dir, now);

        // The check does not depend on the background timer having run: the operation itself
        // notices, so a stalled timer cannot leave the vault open indefinitely.
        let result = session.list("", now + TIMEOUT + Duration::from_secs(1));

        assert!(matches!(result, Err(SessionError::Locked)));
    }

    #[test]
    fn a_locked_session_is_not_idle() {
        let dir = TempDir::new().unwrap();
        let mut session = session_in(&dir);

        // Nothing to lock, so nothing to report — a spurious "just locked" would make the
        // interface flash a lock notice at a user who never unlocked anything.
        assert!(!session.lock_if_idle(Instant::now() + TIMEOUT * 10));
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_save_does_not_leave_a_phantom_credential_in_memory() {
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let mut session = unlocked(&dir, now);
        session.add(draft("saved.com", "u", "p"), now).unwrap();

        std::fs::set_permissions(dir.path(), Permissions::from_mode(0o500)).unwrap();
        let running_as_root = std::fs::File::create(dir.path().join("probe")).is_ok();
        let blocked = session.add(draft("never-saved.com", "u", "p"), now);
        std::fs::set_permissions(dir.path(), Permissions::from_mode(0o700)).unwrap();

        if running_as_root {
            return;
        }

        assert!(blocked.is_err(), "the save must not have been possible");

        // Showing an entry the disk never received is how a user ends up trusting a credential
        // that is not there.
        let sites: Vec<_> = session
            .list("", now)
            .unwrap()
            .into_iter()
            .map(|summary| summary.site)
            .collect();
        assert_eq!(sites, vec!["saved.com"]);
    }

    #[test]
    fn error_messages_do_not_mention_secrets() {
        for error in [
            SessionError::Locked,
            SessionError::NoVault,
            SessionError::VaultAlreadyExists,
            SessionError::WeakMasterPassword {
                minimum: MIN_MASTER_PASSWORD_LEN,
            },
        ] {
            let message = error.to_string().to_lowercase();

            assert!(!message.is_empty());
            assert!(!message.contains("plaintext"));
        }
    }
}
