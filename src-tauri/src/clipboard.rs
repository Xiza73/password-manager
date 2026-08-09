//! Putting a password on the clipboard, and getting it back off.
//!
//! This does not go through `tauri-plugin-clipboard-manager`. The plugin calls `set_text`, which
//! writes without any exclusion markers — and clipboard-history tools (Raycast, Alfred, Maccy,
//! Paste, Klipper) then record the password into their own unencrypted on-disk history, where it
//! stays. Clearing the live clipboard thirty seconds later does nothing about those copies. An
//! attacker with the stolen laptop or the cloud backup reads the password without touching the
//! vault at all, which makes it the widest gap in the whole design.
//!
//! Owning the write means the markers can be set. Owning the [`arboard::Clipboard`] as well is
//! not optional: on X11 the process that set the selection must stay alive to serve it, so a
//! short-lived handle would drop the contents on the floor.

use std::sync::Mutex;

use arboard::Clipboard;

/// Whether the platform can keep this copy out of clipboard-history tools.
///
/// Reported rather than assumed, so the interface can tell the truth on Linux instead of
/// implying a protection that is not there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryExclusion {
    Excluded,
    /// X11 and Wayland have no equivalent of the macOS or Windows markers.
    Unsupported,
}

impl HistoryExclusion {
    /// What this platform can do, independent of any particular write succeeding.
    pub const fn available() -> Self {
        if cfg!(any(target_os = "macos", target_os = "windows")) {
            Self::Excluded
        } else {
            Self::Unsupported
        }
    }

    pub const fn is_excluded(self) -> bool {
        matches!(self, Self::Excluded)
    }
}

/// The application's single clipboard handle.
///
/// `Option` so it can be dropped at exit: arboard requires it, and on X11 dropping is what hands
/// the selection to the desktop's clipboard manager instead of losing it.
pub struct ClipboardHolder(Mutex<Option<Clipboard>>);

impl ClipboardHolder {
    pub fn new() -> Self {
        Self(Mutex::new(Clipboard::new().ok()))
    }

    /// Writes a secret, asking the platform to keep it out of clipboard history.
    pub fn write_secret(&self, text: &str) -> Result<HistoryExclusion, ClipboardUnavailable> {
        self.with(|clipboard| {
            let set = clipboard.set();

            #[cfg(target_os = "macos")]
            // Sets `org.nspasteboard.ConcealedType`, the community marker history tools honour.
            let set = {
                use arboard::SetExtApple;
                set.exclude_from_history()
            };

            #[cfg(target_os = "windows")]
            // `exclude_from_monitoring` alone, not combined with the other two: arboard's own
            // documentation says the narrower flags should not be set alongside it.
            let set = {
                use arboard::SetExtWindows;
                set.exclude_from_monitoring()
            };

            set.text(text).ok()?;

            Some(HistoryExclusion::available())
        })
    }

    /// Clears the clipboard, but only if it still holds `expected`.
    ///
    /// Returns whether it cleared. Clearing unconditionally would throw away whatever the user
    /// copied in the meantime, and silently losing someone's clipboard is a worse bug than
    /// leaving a password on it a little longer.
    pub fn clear_if_unchanged(&self, expected: &str) -> bool {
        self.with(|clipboard| {
            // Unreadable is not the same as unchanged, and guessing wrong destroys data.
            if clipboard.get().text().ok().as_deref() != Some(expected) {
                return None;
            }

            clipboard.clear().ok()?;
            Some(())
        })
        .is_ok()
    }

    /// Drops the handle at shutdown, so X11 hands the selection over rather than dropping it.
    pub fn release(&self) {
        if let Ok(mut held) = self.0.lock() {
            held.take();
        }
    }

    fn with<T>(
        &self,
        action: impl FnOnce(&mut Clipboard) -> Option<T>,
    ) -> Result<T, ClipboardUnavailable> {
        let mut held = self.0.lock().map_err(|_| ClipboardUnavailable)?;
        let clipboard = held.as_mut().ok_or(ClipboardUnavailable)?;

        action(clipboard).ok_or(ClipboardUnavailable)
    }
}

impl Default for ClipboardHolder {
    fn default() -> Self {
        Self::new()
    }
}

/// The clipboard could not be reached. Deliberately carries no detail: the reason is a platform
/// quirk, not something the user can act on differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClipboardUnavailable;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_exclusion_support_for_this_platform() {
        // The interface uses this to decide whether to promise history exclusion, so it must
        // match what the write actually does rather than being optimistic.
        let expected = if cfg!(any(target_os = "macos", target_os = "windows")) {
            HistoryExclusion::Excluded
        } else {
            HistoryExclusion::Unsupported
        };

        assert_eq!(HistoryExclusion::available(), expected);
    }

    #[test]
    fn only_excluded_counts_as_excluded() {
        assert!(HistoryExclusion::Excluded.is_excluded());
        assert!(!HistoryExclusion::Unsupported.is_excluded());
    }
}
