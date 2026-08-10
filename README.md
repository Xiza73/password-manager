# Password Manager

A local-first desktop password manager. The vault is a single encrypted file on your machine —
no account, no server, no sync.

Built with [Tauri v2](https://v2.tauri.app) (Rust core) and React + TypeScript.

## Status

The first release scope is complete: create and unlock a vault, add, edit, search and delete
credentials, generate passwords, copy one to the clipboard, and lock on idle.

| Layer                               | What it does                                      |
| ----------------------------------- | ------------------------------------------------- |
| `src-tauri/src/crypto/kdf.rs`       | Argon2id key derivation (128 MiB, 3 passes)       |
| `src-tauri/src/crypto/cipher.rs`    | AES-256-GCM authenticated encryption              |
| `src-tauri/src/crypto/generator.rs` | Unbiased password generation                      |
| `src-tauri/src/vault/`              | File format, atomic persistence, credential model |
| `src-tauri/src/session.rs`          | Unlocked-vault state machine, idle lock           |
| `src-tauri/src/commands.rs`         | Tauri command surface                             |
| `src/features/`                     | Unlock screen, credential list, entry form        |

The vault format is version 2. It carries a save counter, and a sibling `vault.pwm.seen` file
records the highest one this installation has written. Opening a vault with a lower counter is
reported, not refused — a restored backup looks the same from here, and locking someone out of
credentials they just restored is the worse mistake. The record is unauthenticated, so anyone
who can write both files defeats it; what it reliably catches is a stale copy pushed by a sync
client or a half-restored backup.

Not done: cloud sync, browser extension, mobile builds, importing from another manager,
changing the master password.

## Builds

`npm run tauri build` produces an installer for the machine it runs on and nothing else — Tauri
does not cross-compile, so a Windows `.msi` has to be built on Windows.

`.github/workflows/` covers that. `checks` runs the Rust suite, clippy and rustfmt on Linux,
macOS and Windows for every push to `dev` and `master`; the frontend suite and both dependency
audits run once. `release` fires when a release is **published** — the notes are written by hand,
so create the release first and the workflow attaches the binaries afterwards:

| Platform | Produced                                    |
| -------- | ------------------------------------------- |
| macOS    | `.dmg`, universal (Apple Silicon and Intel) |
| Windows  | `.msi` and an NSIS `-setup.exe`             |
| Linux    | `.deb`, `.rpm`, `.AppImage`                 |

It refuses to build if the tag and the three manifests disagree about the version, and refuses to
publish if a platform produced no installer. A combined `SHA256SUMS.txt` covers every file.

What CI does **not** solve is signing. Every binary it produces is unsigned, so macOS and Windows
will warn before opening one, and nothing ties a download to this repository beyond the checksum.

## Requirements

- Node 20+
- Rust stable (with `clippy` and `rustfmt`: `rustup component add clippy rustfmt`)
- Platform prerequisites for Tauri: https://v2.tauri.app/start/prerequisites/

## Getting started

```bash
npm install
npm run tauri dev
```

If `npm install` reports skipped install scripts, approve them individually —
`esbuild` and `fsevents` are the ones this project needs:

```bash
npm approve-scripts esbuild fsevents
```

## Commands

| Task           | Frontend              | Rust core                                                                        |
| -------------- | --------------------- | -------------------------------------------------------------------------------- |
| Test           | `npm run test:run`    | `cargo test --manifest-path src-tauri/Cargo.toml`                                |
| Lint           | `npm run lint`        | `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings` |
| Format         | `npm run format`      | `cargo fmt --manifest-path src-tauri/Cargo.toml`                                 |
| Typecheck      | `npm run typecheck`   | —                                                                                |
| Audit          | `npm audit`           | `cargo audit --file src-tauri/Cargo.lock`                                        |
| Release bundle | `npm run tauri build` | —                                                                                |

`cargo audit` needs `cargo install cargo-audit --locked`. It reports `unmaintained` warnings for
the GTK3, `glib`, `unic-*` and `proc-macro-error` crates that Tauri brings in; none is in the
cryptographic path and none is actionable here.

## Layout

```
src/           React + TypeScript UI
  lib/ipc.ts   the only place that calls Tauri commands
src-tauri/     Rust core: crypto, vault, commands
```

Development conventions and security rules live in [CLAUDE.md](./CLAUDE.md).

## Security

This is a password manager, so the rules are strict and non-negotiable: no hand-rolled
cryptography, no secret ever logged or serialised, key material zeroized on drop, and the
capability set in `src-tauri/capabilities/` grants the minimum. See `CLAUDE.md` for the full list.
