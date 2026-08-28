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
use crate::vault::format::{decode, decode_with, read_counter, SealingKey, VaultError, FIRST_SAVE};
use crate::vault::storage::{
    exists, highest_seen, read_sealed, remove_vault, save_sealed, StorageError,
};

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

/// What opening a vault reports back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Unlocked {
    /// True when this vault carries a lower save counter than one already opened here.
    ///
    /// Reported rather than refused. A restore from backup is indistinguishable from an attack
    /// at this level, and locking someone out of credentials they just restored is the worse
    /// mistake of the two.
    pub rolled_back: bool,
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
    /// The counter the next save will write.
    next_save: u64,
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
        save_sealed(&self.path, &sealing, FIRST_SAVE, &data.to_bytes()?)?;

        self.state = State::Open(Open {
            sealing,
            data,
            last_seen: now,
            next_save: FIRST_SAVE + 1,
        });

        Ok(())
    }

    /// Opens an existing vault, reporting whether it is older than the last one seen here.
    pub fn unlock(
        &mut self,
        password: &SecretString,
        now: Instant,
    ) -> Result<Unlocked, SessionError> {
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

        // Only trustworthy once the body has authenticated: the counter is bound as associated
        // data, so reading it earlier would be reading an attacker's number.
        let counter = read_counter(&file)?;
        let highest = highest_seen(&self.path);
        let rolled_back = highest.is_some_and(|seen| counter < seen);

        self.state = State::Open(Open {
            sealing,
            data,
            last_seen: now,
            // Step past whichever is higher. A legitimate restore then repairs itself on the
            // first save instead of warning forever, and a counter is never reused.
            next_save: counter.max(highest.unwrap_or(0)) + 1,
        });

        Ok(Unlocked { rolled_back })
    }

    /// Deletes the vault and returns the session to its first-run state.
    ///
    /// This is the only way back in when the master password is lost. There is no recovery — the
    /// key derives from the password and nothing else — so the honest alternative is to discard
    /// the vault and start over. It destroys every credential, and nothing about that is
    /// reversible.
    pub fn reset(&mut self) -> Result<(), SessionError> {
        // Delete before locking. A failed delete leaves the session as it was rather than closing
        // a vault the user did not ask to close.
        remove_vault(&self.path)?;

        // Drop any key and decrypted contents still in memory. On the unlock screen the session
        // is already locked, so this is a no-op there, but it makes the postcondition hold from
        // any state.
        self.lock();

        Ok(())
    }

    /// Re-keys the open vault under a new master password, keeping every credential.
    ///
    /// The current password is required and verified against the file on disk, not taken on trust
    /// from the open session. Unlocking already proved someone knew it once; re-keying the thing
    /// that guards every credential should require proving it again, now — otherwise a vault left
    /// open and unattended could have its master password changed out from under its owner.
    ///
    /// The new key is derived with a fresh salt at this build's cost, so a change also lifts an
    /// older vault's KDF cost to the current recommendation. The vault stays open under the new
    /// key: nothing is re-locked, and the next save already seals with it.
    pub fn change_master_password(
        &mut self,
        current: &SecretString,
        next: &SecretString,
        now: Instant,
    ) -> Result<(), SessionError> {
        // Must be open and not idle. The borrow is dropped at once; the re-key needs `&mut self`.
        self.active(now)?;

        // Re-authenticate before evaluating the request. A wrong current password comes back as
        // `Unauthentic`, the same answer a bad unlock gives — the crypto cannot tell the two
        // apart and neither should the caller.
        let file = read_sealed(&self.path)?;
        decode(current.expose().as_bytes(), &file)?;

        check_master_password(next)?;

        // A fresh salt is drawn here, so the re-keyed file shares nothing with the old one beyond
        // its contents.
        let sealing = SealingKey::create(next.expose().as_bytes(), self.params)?;

        let State::Open(open) = &mut self.state else {
            return Err(SessionError::Locked);
        };

        let body = open.data.to_bytes()?;
        // Written atomically past the highest counter seen. If this fails, the old file — under
        // the old password — is left intact, and the session keeps its old key below.
        save_sealed(&self.path, &sealing, open.next_save, &body)?;

        // Only now that the new file is safely on disk does the session adopt the new key.
        open.sealing = sealing;
        open.next_save += 1;

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
                        save_sealed(&self.path, &open.sealing, open.next_save, &body)
                            .map_err(SessionError::from)
                    })
            }
        };

        if result.is_ok() {
            if let State::Open(open) = &mut self.state {
                open.next_save += 1;
            }
        } else if self.reload().is_err() {
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
    fn a_current_vault_reports_no_rollback() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let mut session = unlocked(&dir, now);
        session.add(draft("a.com", "u", "p"), now).unwrap();
        session.lock();

        let opened = session.unlock(&secret(MASTER), now).unwrap();

        assert!(!opened.rolled_back);
    }

    #[test]
    fn a_first_run_reports_no_rollback() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        unlocked(&dir, now);
        // No record of any previous save — a fresh installation opening an existing vault, or a
        // record that was wiped. Silence, not an accusation.
        std::fs::remove_file(dir.path().join("vault.pwm.seen")).unwrap();

        let opened = session_in(&dir).unlock(&secret(MASTER), now).unwrap();

        assert!(!opened.rolled_back);
    }

    #[test]
    fn reports_a_vault_that_was_replaced_with_an_older_copy() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let path = dir.path().join("vault.pwm");
        let mut session = unlocked(&dir, now);
        let backup = std::fs::read(&path).unwrap();

        session.add(draft("a.com", "u", "p"), now).unwrap();
        session.add(draft("b.com", "u", "p"), now).unwrap();
        session.lock();
        // A sync client pushing a stale copy, or a half-restored backup.
        std::fs::write(&path, &backup).unwrap();

        let opened = session.unlock(&secret(MASTER), now).unwrap();

        assert!(opened.rolled_back);
    }

    #[test]
    fn an_older_vault_still_opens() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let path = dir.path().join("vault.pwm");
        let mut session = unlocked(&dir, now);
        let id = session.add(draft("kept.com", "u", "p"), now).unwrap();
        let backup = std::fs::read(&path).unwrap();
        session.add(draft("later.com", "u", "p"), now).unwrap();
        session.lock();
        std::fs::write(&path, &backup).unwrap();

        session.unlock(&secret(MASTER), now).unwrap();

        // Refusing would lock someone out of credentials they just restored, which is worse
        // than the attack the check exists to notice. It reports; it does not decide.
        assert_eq!(session.reveal(id, now).unwrap().site, "kept.com");
    }

    #[test]
    fn a_restored_vault_stops_complaining_once_it_is_used() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let path = dir.path().join("vault.pwm");
        let mut session = unlocked(&dir, now);
        let backup = std::fs::read(&path).unwrap();
        session.add(draft("a.com", "u", "p"), now).unwrap();
        session.add(draft("b.com", "u", "p"), now).unwrap();
        session.lock();
        std::fs::write(&path, &backup).unwrap();

        assert!(session.unlock(&secret(MASTER), now).unwrap().rolled_back);
        // Saving steps the counter past the highest ever recorded, so the restore repairs
        // itself rather than warning on every unlock from here on.
        session.add(draft("c.com", "u", "p"), now).unwrap();
        session.lock();

        assert!(!session.unlock(&secret(MASTER), now).unwrap().rolled_back);
    }

    #[test]
    fn never_writes_the_same_counter_twice() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let path = dir.path().join("vault.pwm");
        let mut session = unlocked(&dir, now);

        let mut seen = Vec::new();
        for site in ["a.com", "b.com", "c.com"] {
            session.add(draft(site, "u", "p"), now).unwrap();
            seen.push(read_counter(&std::fs::read(&path).unwrap()).unwrap());
        }

        // A reused counter would let a later vault pass for an earlier one and vice versa.
        let mut sorted = seen.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, seen, "counters must be strictly increasing");
    }

    const NEW_MASTER: &str = "a brand new master password";

    #[test]
    fn changing_the_master_password_reopens_the_vault_under_the_new_one() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let mut session = unlocked(&dir, now);
        let id = session
            .add(draft("github.com", "octocat", "hunter2"), now)
            .unwrap();

        session
            .change_master_password(&secret(MASTER), &secret(NEW_MASTER), now)
            .unwrap();
        session.lock();

        // The old password no longer opens it — the key it derived is gone from the file.
        assert!(matches!(
            session.unlock(&secret(MASTER), now),
            Err(SessionError::Vault(VaultError::Unauthentic))
        ));
        // The new one does, and every credential survived the re-key untouched.
        session.unlock(&secret(NEW_MASTER), now).unwrap();
        assert_eq!(
            session.reveal(id, now).unwrap().password.expose(),
            "hunter2"
        );
    }

    #[test]
    fn a_password_change_keeps_the_vault_open_under_the_new_key() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let mut session = unlocked(&dir, now);

        session
            .change_master_password(&secret(MASTER), &secret(NEW_MASTER), now)
            .unwrap();

        // No re-unlock: the session adopted the new key in place, and edits from here seal under
        // it — a separate session opening with the new password sees them.
        assert!(session.is_unlocked());
        session.add(draft("a.com", "u", "p"), now).unwrap();
        session.lock();
        session.unlock(&secret(NEW_MASTER), now).unwrap();
        assert_eq!(session.list("", now).unwrap().len(), 1);
    }

    #[test]
    fn refuses_a_password_change_with_the_wrong_current_password() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let mut session = unlocked(&dir, now);

        let result = session.change_master_password(
            &secret("not the current one"),
            &secret(NEW_MASTER),
            now,
        );

        // Re-authentication is what stops a change made at an unattended open vault, so a wrong
        // current password is refused with the same answer as a bad unlock.
        assert!(matches!(
            result,
            Err(SessionError::Vault(VaultError::Unauthentic))
        ));
        // Nothing changed: the original password still opens the vault.
        session.lock();
        session.unlock(&secret(MASTER), now).unwrap();
        assert!(session.is_unlocked());
    }

    #[test]
    fn refuses_a_weak_new_master_password() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let mut session = unlocked(&dir, now);

        let result = session.change_master_password(&secret(MASTER), &secret("short"), now);

        assert!(matches!(
            result,
            Err(SessionError::WeakMasterPassword { minimum })
                if minimum == MIN_MASTER_PASSWORD_LEN
        ));
        // The vault was left under its original password, unchanged.
        session.lock();
        session.unlock(&secret(MASTER), now).unwrap();
    }

    #[test]
    fn refuses_a_password_change_while_locked() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let mut session = unlocked(&dir, now);
        session.lock();

        let result = session.change_master_password(&secret(MASTER), &secret(NEW_MASTER), now);

        assert!(matches!(result, Err(SessionError::Locked)));
    }

    #[test]
    fn a_changed_password_does_not_leave_the_vault_looking_rolled_back() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let mut session = unlocked(&dir, now);
        session.add(draft("a.com", "u", "p"), now).unwrap();

        session
            .change_master_password(&secret(MASTER), &secret(NEW_MASTER), now)
            .unwrap();
        session.lock();

        // The re-key writes past the highest counter seen, so it is strictly newer than what it
        // replaced rather than an apparent rollback.
        let opened = session.unlock(&secret(NEW_MASTER), now).unwrap();
        assert!(!opened.rolled_back);
    }

    #[test]
    fn resetting_deletes_the_vault_and_returns_to_first_run() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let mut session = unlocked(&dir, now);
        session.add(draft("a.com", "u", "p"), now).unwrap();
        session.lock();

        session.reset().unwrap();

        assert!(!session.vault_exists());
        assert!(!session.is_unlocked());
        // The credentials are gone, not hidden: a vault created afterwards opens empty.
        session.create(&secret(MASTER), now).unwrap();
        assert!(session.list("", now).unwrap().is_empty());
    }

    #[test]
    fn a_vault_created_after_a_reset_does_not_look_like_a_rollback() {
        let dir = TempDir::new().unwrap();
        let now = Instant::now();
        let mut session = unlocked(&dir, now);
        // Push the counter up, so a surviving `.seen` record would out-number a fresh vault.
        for site in ["a.com", "b.com", "c.com"] {
            session.add(draft(site, "u", "p"), now).unwrap();
        }
        session.lock();

        session.reset().unwrap();

        // Start over — a lost password is the reason this exists — with a different master.
        session.create(&secret("a different master"), now).unwrap();
        session.lock();
        let opened = session.unlock(&secret("a different master"), now).unwrap();

        // Had the reset spared the `.seen` file, the new vault would carry a lower counter than
        // the deleted one and cry rollback on every unlock until it happened to save past it.
        assert!(!opened.rolled_back);
    }

    #[test]
    fn resetting_with_no_vault_is_harmless() {
        let dir = TempDir::new().unwrap();
        let mut session = session_in(&dir);

        // Nothing to delete; the end state is identical either way.
        assert!(session.reset().is_ok());
        assert!(!session.vault_exists());
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
