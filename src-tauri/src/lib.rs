pub mod clipboard;
pub mod commands;
pub mod crypto;
pub mod secret;
pub mod session;
pub mod vault;

use std::sync::Mutex;
use std::time::{Duration, Instant};

use tauri::{Emitter, Manager};

use crate::clipboard::ClipboardHolder;
use crate::commands::AppState;
use crate::crypto::kdf::KdfParams;
use crate::session::Session;

/// How long an open vault survives without being used.
///
/// Short enough that a walked-away-from laptop closes itself, long enough not to interrupt
/// someone working through a list of accounts.
const IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// How often the idle check runs. The commands check too, so this only matters while nobody is
/// touching the application — which is exactly the case it exists for.
const LOCK_CHECK_INTERVAL: Duration = Duration::from_secs(15);

/// Emitted when the idle timer closes the vault, so the interface can leave the screen it is on.
pub const VAULT_LOCKED_EVENT: &str = "vault-locked";

const VAULT_FILE_NAME: &str = "vault.pwm";

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let directory = app.path().app_data_dir()?;
            std::fs::create_dir_all(&directory)?;

            app.manage(AppState(Mutex::new(Session::new(
                directory.join(VAULT_FILE_NAME),
                IDLE_TIMEOUT,
                KdfParams::RECOMMENDED,
            ))));

            // Held by the Rust side only, and deliberately not the clipboard plugin — see
            // `crate::clipboard`. Nothing in the interface can reach it, so no clipboard
            // permission appears in `capabilities/` and the WebView cannot read the clipboard
            // even while the vault is open.
            app.manage(ClipboardHolder::new());

            spawn_idle_lock(app.handle().clone());

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::minimum_master_password_length,
            commands::vault_exists,
            commands::is_unlocked,
            commands::create_vault,
            commands::unlock,
            commands::lock,
            commands::reset_vault,
            commands::list_entries,
            commands::reveal_entry,
            commands::add_entry,
            commands::update_entry,
            commands::remove_entry,
            commands::generate_password,
            commands::copy_password,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                // arboard wants the handle dropped before the process ends, and on X11 dropping
                // is what hands the selection to the desktop's clipboard manager rather than
                // losing it. Tauri does not run destructors on exit, so this is explicit.
                app.state::<ClipboardHolder>().release();
            }
        });
}

/// Closes an idle vault even when nothing is calling in.
fn spawn_idle_lock(handle: tauri::AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(LOCK_CHECK_INTERVAL);

        let state = handle.state::<AppState>();
        // A panic elsewhere must not be the reason a vault stays open, so a poisoned lock is
        // taken anyway — the only thing done with it is closing the vault.
        let mut session = match state.0.lock() {
            Ok(session) => session,
            Err(poisoned) => poisoned.into_inner(),
        };

        if session.lock_if_idle(Instant::now()) {
            let _ = handle.emit(VAULT_LOCKED_EVENT, ());
        }
    });
}
