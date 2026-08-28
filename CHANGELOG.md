# Changelog

Notable changes to this project. The format follows [Keep a Changelog](https://keepachangelog.com/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/).

A major version bump means the vault format changed in a way an older build cannot read.

## [Unreleased]

### Added

- **Change the master password** from inside an open vault, without losing a credential. The
  vault is re-encrypted under a key derived from the new password with a fresh salt — and at the
  current KDF cost, so a change also upgrades an older vault's cost. The current password is
  required and verified in Rust, so a vault left open and unattended cannot have its master
  password changed out from under its owner. The vault stays open under the new key; no re-unlock.
- **Delete the vault and start over**, from a "Forgot your master password?" affordance on the
  unlock screen. There is no password recovery and there never will be — the key derives from the
  master password and nothing else, so anything that could reopen the vault for you could reopen
  it for anyone. This is the honest alternative: it recovers nothing and discards everything,
  behind a two-step confirmation that states the cost in plain words. It deletes the counter
  record along with the vault, so a vault created next does not masquerade as a rollback of the
  deleted one.

## [0.4.1] — 2026-08-10

Nothing in the application changed. The installers behave exactly as 0.4.0's do; what this
release proves is that a release now publishes checksums that verify.

### Fixed

- **The checksums published with 0.4.0 verified nothing.** The bundler names its output with a
  space (`Password Manager_0.4.0_universal.dmg`) and GitHub turns that space into a dot when the
  asset is uploaded, so every name in `SHA256SUMS.txt` referred to a file that could not be
  downloaded. `shasum -c` matched none of them. CI had verified the list — on the runner, before
  the rename, where the names still agreed. The release now strips the spaces before hashing, and
  fails outright if a space survives into the list. The 0.4.0 checksums have been replaced; the
  binaries were never affected and their hashes are unchanged.

### Added

- Screenshots in the README: the unlock screen and an open vault, one per palette. They are
  taken from the real components with invented credentials behind a stubbed IPC layer. They
  carry the 0.4.0 title bar, which is the version they were captured against.

## [0.4.0] — 2026-08-10

**Nothing about the application changed.** This release exists so the published binaries cover
every platform, which until now they did not.

### Added

- **Installers for macOS, Windows and Linux**, built by CI on each platform. Tauri does not
  cross-compile, so every earlier release shipped whatever the developer's laptop could produce —
  an Apple Silicon `.dmg` and nothing else. macOS is now a universal binary, so it runs on Intel
  too.
- **Checks run on all three platforms** for every change. Two `cfg(not(unix))` branches in the
  vault's persistence and the Windows clipboard path had never been compiled anywhere before
  this; they compile, and their tests pass.

### Notes

`tests/ipc_commands.rs` does not run on Windows: its binary fails to load inside Tauri's mock
runtime. What it covers has no platform-specific branch, and Linux and macOS run all of it.

Compiling is not the same as verifying. `sync_parent_directory` on Windows does nothing, on the
grounds that the rename is durable without it — that claim is still unverified.

Every binary is unsigned. CI does not change that.

## [0.3.0] — 2026-08-10

### Changed

- **The application fills the window.** No desktop backdrop behind it, and with nothing behind
  it the outer bevel and drop shadow went too. The body scrolls rather than the page, so the
  title bar stays put; the credential list takes the height it is given instead of stopping at a
  fixed cap.

### Removed

- **The window controls and the File / Edit / Vault / Help menu.** They came from the reference
  design and were never wired to anything. A Tauri window is already framed by the operating
  system, and chrome that looks like a control and answers to nothing is a small lie repeated on
  every screen. The strip that held the menu keeps the theme toggle, which works.

### Notes

Presentation only. No Rust changed at all, and the vault format stays at version 2, so vaults
written by 0.1.0 and 0.2.0 open without migration.

## [0.2.0] — 2026-08-10

### Changed

- **The interface is now a late-nineties desktop application.** Beveled surfaces drawn with
  inset shadows rather than borders, a title bar, a menu strip, a column list and a status bar.
  Two palettes: near-black with a gold accent, and the classic teal desktop with a navy title
  bar. The theme follows the operating system until you pick one from the menu strip, and is
  remembered after that.
- Form labels carry trailing colons, and the credential list is laid out in columns rather than
  as a stack of cards.

### Notes

Presentation only. The vault format is unchanged at version 2, so vaults written by 0.1.0 open
without migration. The list still carries no passwords — the reference design showed them inline
in the table, and that is exactly what the listing type exists to prevent.

## [0.1.0] — 2026-08-09

First release. Everything in the agreed scope works; nothing is signed yet.

### Added

- **Encrypted vault.** Argon2id derives the key (128 MiB, 3 passes, one lane), AES-256-GCM
  seals the contents. The cost parameters travel in the vault header, so raising them later
  never strands a vault written today.
- **Credentials.** Create, edit, search and delete entries with a site, username, password and
  notes. Listing returns a type with no password field, so the interface holds an index of the
  whole vault without a secret crossing into it.
- **Password generator.** Rejection sampling from the system CSPRNG — no modulo bias — with
  toggles for character classes and look-alike characters. Reports entropy in bits rather than
  a "strong" verdict.
- **Clipboard copy.** Handled entirely in Rust, so the password never enters the WebView. Marked
  so clipboard-history tools ignore it on macOS and Windows, and cleared after 30 seconds — but
  only if the clipboard still holds what was written.
- **Auto-lock.** The vault closes after five minutes idle, dropping the key and the decrypted
  contents. Checked on every command as well as by a background timer, so a stalled timer cannot
  leave it open.
- **Rollback detection.** A save counter in the header, plus a record of the highest one seen,
  notice a vault replaced with an older copy. Reported, never refused: a restored backup looks
  the same from here, and locking someone out of what they just restored is the worse mistake.

### Security notes

- The vault file never leaves the machine. There is no account, no sync and no telemetry.
- The master password is never stored — only the key derived from it, and only while unlocked.
- Vault files are created `0600`, and every save goes through a temporary file and a rename so
  an interrupted write cannot destroy the previous vault.
- The WebView is granted `core:default` and nothing else. It cannot read the clipboard or the
  filesystem.

### Known limitations

- **Nothing is signed.** macOS and Windows will warn before opening a downloaded build, and
  there is no way to verify that a binary came from this repository. Build from source, or
  check the published SHA-256.
- **The master password cannot be changed.** Rotating it means creating a new vault.
- **The rollback record is unauthenticated.** Anyone who can write both the vault and its
  `.seen` sibling defeats the check. It reliably catches a stale sync copy or a partial restore,
  not a deliberate attacker with filesystem access.
- The master password unavoidably exists in unwiped memory in the WebView and in the IPC
  payload. It is never stored, never logged, and discarded as soon as the key is derived.

[0.4.1]: https://github.com/Xiza73/password-manager/releases/tag/v0.4.1
[0.4.0]: https://github.com/Xiza73/password-manager/releases/tag/v0.4.0
[0.3.0]: https://github.com/Xiza73/password-manager/releases/tag/v0.3.0
[0.2.0]: https://github.com/Xiza73/password-manager/releases/tag/v0.2.0
[0.1.0]: https://github.com/Xiza73/password-manager/releases/tag/v0.1.0
