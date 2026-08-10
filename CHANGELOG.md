# Changelog

Notable changes to this project. The format follows [Keep a Changelog](https://keepachangelog.com/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/).

A major version bump means the vault format changed in a way an older build cannot read.

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

[0.2.0]: https://github.com/Xiza73/password-manager/releases/tag/v0.2.0
[0.1.0]: https://github.com/Xiza73/password-manager/releases/tag/v0.1.0
