//! The Tauri command surface.
//!
//! Every function here does the same three things: take the lock, call one [`Session`] method,
//! translate the error. There is no logic to test in this file because there is no logic in it —
//! all of it lives in [`crate::session`], which needs no window to exercise.
//!
//! The WebView is treated as untrusted. It chooses *which* operation runs and supplies its
//! arguments; it never holds the key, the vault contents, or the decision about whether the
//! vault is open.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroizing;

use crate::clipboard::ClipboardHolder;
use crate::crypto::generator::{generate, GeneratedPassword, GeneratorError, GeneratorOptions};
use crate::secret::SecretString;
use crate::session::{
    RevealedCredential, Session, SessionError, Unlocked, MIN_MASTER_PASSWORD_LEN,
};
use crate::vault::entries::{CredentialDraft, CredentialSummary, EntryError, EntryId};
use crate::vault::format::VaultError;

pub struct AppState(pub Mutex<Session>);

/// The error shape the interface receives.
///
/// `code` is what the interface branches on; `message` is what it may show. Neither ever carries
/// a secret, a path, or a hint about how close a password guess was.
#[derive(Debug, Serialize)]
pub struct IpcError {
    pub code: String,
    pub message: String,
}

impl IpcError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
        }
    }
}

impl From<SessionError> for IpcError {
    fn from(error: SessionError) -> Self {
        let code = match &error {
            SessionError::Locked => "locked",
            SessionError::NoVault => "no_vault",
            SessionError::VaultAlreadyExists => "vault_exists",
            SessionError::WeakMasterPassword { .. } => "weak_password",
            SessionError::Entry(EntryError::NotFound) => "not_found",
            SessionError::Entry(EntryError::SiteRequired) => "site_required",
            // A wrong master password and a tampered file are one answer, all the way up. See
            // `CipherError::Unauthentic`.
            SessionError::Vault(VaultError::Unauthentic) => "unauthentic",
            SessionError::Vault(VaultError::NotAVault) => "not_a_vault",
            SessionError::Vault(VaultError::UnsupportedVersion(_)) => "unsupported_version",
            SessionError::Entry(EntryError::UnsupportedBodyVersion(_)) => "unsupported_version",
            SessionError::Vault(VaultError::Malformed) | SessionError::Entry(_) => "malformed",
            SessionError::Storage(_) => "storage",
            SessionError::Vault(_) => "internal",
        };

        Self::new(code, error.to_string())
    }
}

/// Runs `operation` against the session.
///
/// A poisoned lock means a panic happened while the vault was open, so the state behind it
/// cannot be trusted. The vault is closed before anything else is allowed to touch it.
fn with_session<T>(
    state: &State<'_, AppState>,
    operation: impl FnOnce(&mut Session) -> Result<T, SessionError>,
) -> Result<T, IpcError> {
    match state.0.lock() {
        Ok(mut session) => operation(&mut session).map_err(IpcError::from),
        Err(poisoned) => {
            poisoned.into_inner().lock();
            Err(IpcError::new(
                "internal",
                "the vault was closed after an internal error",
            ))
        }
    }
}

#[tauri::command]
pub fn minimum_master_password_length() -> usize {
    MIN_MASTER_PASSWORD_LEN
}

#[tauri::command]
pub fn vault_exists(state: State<'_, AppState>) -> Result<bool, IpcError> {
    with_session(&state, |session| Ok(session.vault_exists()))
}

#[tauri::command]
pub fn is_unlocked(state: State<'_, AppState>) -> Result<bool, IpcError> {
    // Reported by the Rust side rather than tracked in the interface: a lock that only the
    // interface knows about is a lock an attacker can undo with the developer tools.
    with_session(&state, |session| Ok(session.is_unlocked()))
}

#[tauri::command]
pub fn create_vault(password: SecretString, state: State<'_, AppState>) -> Result<(), IpcError> {
    with_session(&state, |session| session.create(&password, Instant::now()))
}

#[tauri::command]
pub fn unlock(password: SecretString, state: State<'_, AppState>) -> Result<Unlocked, IpcError> {
    // Succeeds even when the vault turns out to be older than the last one opened here; the
    // answer says so rather than refusing. See `Unlocked::rolled_back`.
    with_session(&state, |session| session.unlock(&password, Instant::now()))
}

#[tauri::command]
pub fn lock(state: State<'_, AppState>) -> Result<(), IpcError> {
    with_session(&state, |session| {
        session.lock();
        Ok(())
    })
}

#[tauri::command]
pub fn list_entries(
    query: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<CredentialSummary>, IpcError> {
    // Summaries carry no password, so this can be held by the interface for as long as it likes.
    with_session(&state, |session| {
        session.list(query.as_deref().unwrap_or_default(), Instant::now())
    })
}

#[tauri::command]
pub fn reveal_entry(
    id: EntryId,
    state: State<'_, AppState>,
) -> Result<RevealedCredential, IpcError> {
    // The one command that hands a secret to the interface, and it hands over exactly one.
    with_session(&state, |session| session.reveal(id, Instant::now()))
}

#[tauri::command]
pub fn add_entry(draft: CredentialDraft, state: State<'_, AppState>) -> Result<EntryId, IpcError> {
    with_session(&state, |session| session.add(draft, Instant::now()))
}

#[tauri::command]
pub fn update_entry(
    id: EntryId,
    draft: CredentialDraft,
    state: State<'_, AppState>,
) -> Result<(), IpcError> {
    with_session(&state, |session| session.update(id, draft, Instant::now()))
}

#[tauri::command]
pub fn remove_entry(id: EntryId, state: State<'_, AppState>) -> Result<(), IpcError> {
    with_session(&state, |session| session.remove(id, Instant::now()))
}

#[tauri::command]
pub fn generate_password(options: GeneratorOptions) -> Result<GeneratedPassword, IpcError> {
    generate(options).map_err(IpcError::from)
}

/// How long a copied password stays on the clipboard.
///
/// Long enough to switch windows and paste, short enough that it is gone before the machine is
/// left alone.
pub const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);

/// What the interface is told after a copy, so it can say something true about it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CopyOutcome {
    pub seconds_until_clear: u64,
    /// False on Linux, where no marker exists. The interface must not promise what the platform
    /// cannot deliver.
    pub excluded_from_history: bool,
}

/// Copies a credential's password to the clipboard, and takes it back off again.
///
/// The password is read, written and cleared entirely in Rust: for the common case — copy it,
/// paste it somewhere — it never enters the WebView at all.
#[tauri::command]
pub fn copy_password(
    id: EntryId,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CopyOutcome, IpcError> {
    let copied = with_session(&state, |session| {
        Ok(session.reveal(id, Instant::now())?.password)
    })?;

    // `Zeroizing`, not a plain `String`. The copy handed to the timer thread outlives the vault
    // being locked — the idle timer can fire seconds after a copy, drop the key, relock the
    // interface, and leave this one credential in plaintext for the rest of the countdown.
    // A `String` would be released to the allocator with the password intact.
    let text = Zeroizing::new(copied.expose().to_owned());

    let exclusion = app
        .state::<ClipboardHolder>()
        .write_secret(&text)
        .map_err(|_| IpcError::new("clipboard", "the clipboard could not be written"))?;

    schedule_clipboard_clear(app.clone(), text);

    Ok(CopyOutcome {
        seconds_until_clear: CLIPBOARD_CLEAR_AFTER.as_secs(),
        excluded_from_history: exclusion.is_excluded(),
    })
}

/// Clears the clipboard later, but only if it still holds what was put there.
///
/// This runs in Rust rather than behind a timer in the interface on purpose: a `setTimeout` dies
/// with the window, and the password would stay on the clipboard until something else replaced
/// it.
fn schedule_clipboard_clear(app: AppHandle, copied: Zeroizing<String>) {
    std::thread::spawn(move || {
        std::thread::sleep(CLIPBOARD_CLEAR_AFTER);

        app.state::<ClipboardHolder>().clear_if_unchanged(&copied);
        // `copied` is wiped here, when the thread ends.
    });
}

impl From<GeneratorError> for IpcError {
    fn from(error: GeneratorError) -> Self {
        let code = match error {
            GeneratorError::NoCharacterClasses => "no_character_classes",
            GeneratorError::LengthOutOfRange { .. } => "length_out_of_range",
            GeneratorError::RandomUnavailable => "random_unavailable",
            GeneratorError::Exhausted => "internal",
        };

        Self::new(code, error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::clipboard::HistoryExclusion;

    #[test]
    fn a_copy_reports_whether_the_platform_can_hide_it_from_history() {
        let outcome = CopyOutcome {
            seconds_until_clear: CLIPBOARD_CLEAR_AFTER.as_secs(),
            excluded_from_history: HistoryExclusion::available().is_excluded(),
        };

        assert_eq!(outcome.seconds_until_clear, 30);
        assert_eq!(
            outcome.excluded_from_history,
            cfg!(any(target_os = "macos", target_os = "windows"))
        );
    }
}
