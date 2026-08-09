# Password Manager

## Project Context

A local-first desktop password manager built with Tauri v2 (Rust core) and React (TypeScript UI).

**Problem it solves:** users need credentials stored under their own control, encrypted at rest,
with no cloud account and no third-party service holding the vault.

**Non-goals (for now):** cloud sync, multi-user accounts, browser extension, mobile builds.

**Trust model:** the vault file never leaves the machine. Plaintext secrets exist only in memory,
only while the vault is unlocked. The master password is never persisted anywhere.

## Users and Scope (MVP)

Single user, single machine, one vault file.

1. **Vault + master password** — create and unlock an encrypted vault. Argon2id for key derivation,
   AES-256-GCM for the vault payload.
2. **Credential CRUD** — create, list, edit and delete entries (site, username, password, notes).
3. **Password generator** — configurable length, symbol/digit/ambiguous-character toggles,
   copy to clipboard with automatic clear.
4. **Auto-lock and search** — lock the vault after inactivity, filter entries by site or username.

Anything outside this list is post-MVP. Do not build it unless asked.

## Stack and Tooling

| Layer         | Choice                                          |
| ------------- | ----------------------------------------------- |
| Shell         | Tauri v2                                        |
| Core / crypto | Rust (2021 edition)                             |
| UI            | React 19 + TypeScript (strict)                  |
| Bundler       | Vite                                            |
| UI tests      | Vitest + React Testing Library                  |
| Core tests    | `cargo test`                                    |
| Lint / format | ESLint + Prettier, `cargo clippy` + `cargo fmt` |

Single package. This is **not** a monorepo: one npm root plus one Cargo crate in `src-tauri/`.

## Key Commands

```bash
npm run tauri dev       # dev       — Vite + Tauri window with hot reload
npm run tauri build     # build     — release bundle for the host platform
npm run build           # build     — frontend only (tsc + vite build)
npm run test            # test      — Vitest, watch mode
npm run test:run        # test      — Vitest, single pass (use this in checks)
npm run test:coverage   # test      — Vitest with v8 coverage
npm run typecheck       # typecheck — tsc --noEmit
npm run lint            # lint      — ESLint
npm run format          # format    — Prettier, writes in place
```

The Rust core is a separate crate, so its commands need `--manifest-path`:

```bash
cargo test    --manifest-path src-tauri/Cargo.toml
cargo clippy  --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo fmt     --manifest-path src-tauri/Cargo.toml
```

Before any commit, both test suites and both linters must pass.

`npm install` will not run dependency install scripts unless they are approved in the
`allowScripts` field of `package.json` (npm 11.16+). Approve one at a time with
`npm approve-scripts <pkg>` — never `--all`.

## Code Conventions

### General

- TypeScript `strict: true`. No `any`. No `@ts-ignore` without a comment explaining why.
- Rust: no `unwrap()` or `expect()` in code paths reachable from a Tauri command. Return `Result`
  and map to a serializable error type.
- Comments explain **why**, never **what**. Delete commented-out code.
- No barrel files (`index.ts` re-exports) — they break tree-shaking and hide dependencies.

### Frontend structure

- Feature-first: `src/features/<feature>/` holds components, hooks and tests for that feature.
- Container / presentational split: components that fetch or hold state do not render markup
  directly; presentational components take props and stay pure.
- Shared primitives live in `src/components/`. Cross-cutting helpers in `src/lib/`.
- All Tauri IPC goes through a single typed layer in `src/lib/ipc.ts`. Components never call
  `invoke` directly.

### Tauri v2 specifics

- Import `invoke` from `@tauri-apps/api/core` — **not** `/tauri` (that is v1).
- Emitting from Rust requires `use tauri::Emitter;` then `app.emit(...)`.
- Permissions live in `src-tauri/capabilities/*.json`. There is no `allowlist` in v2.
- Application logic lives in `src-tauri/src/lib.rs` (`pub fn run()`); `main.rs` stays a thin caller.
- Config keys: `build.frontendDist`, `build.devUrl`, `app.*`, and `bundle` at the top level.

### Security rules (non-negotiable)

- Never log, print, or serialize a plaintext secret, the master password, or a derived key.
- Cryptographic material is wrapped in `Zeroizing` / implements `Drop` with zeroization.
- Never roll custom crypto. Use vetted crates (`argon2`, `aes-gcm`, `rand`, `zeroize`).
- Never send the master password over IPC. Derive the key in Rust; the UI sends it once to unlock
  and keeps no copy.
- Vault files, key material and `.env` are never committed. Test fixtures use throwaway values.
- Clipboard writes carry a timed clear.

### Testing

Strict TDD: write the failing test first, then the implementation.

- Test behaviour, not implementation details. No assertions on internal state or call counts
  unless the call itself is the contract.
- Every crypto function gets tests for the happy path, wrong password, and tampered ciphertext
  (AEAD authentication must fail).
- React tests use React Testing Library queries by role/label, never by class name or test id
  when an accessible query exists.

### Git

Conventional Commits, imperative mood, no scope invention:

```
feat(vault): add Argon2id key derivation
fix(generator): exclude ambiguous characters when flag is set
test(crypto): cover tampered ciphertext rejection
refactor(ui): extract EntryList presentational component
chore(deps): bump tauri to 2.1
```

Never add AI attribution or `Co-Authored-By` trailers.

## Repository Structure

```
password-manager/
├── src/                      # React + TypeScript UI
│   ├── components/           # shared presentational primitives
│   ├── features/             # vault/, entries/, generator/ — feature-first
│   ├── lib/                  # ipc.ts (typed Tauri bridge), helpers
│   └── main.tsx
├── src-tauri/                # Rust core
│   ├── src/
│   │   ├── main.rs           # thin entry point
│   │   ├── lib.rs            # pub fn run() — builder + handlers
│   │   ├── commands/         # #[tauri::command] handlers
│   │   ├── crypto/           # KDF, AEAD, zeroization
│   │   └── vault/            # vault model and persistence
│   ├── capabilities/         # v2 permissions per window
│   ├── tauri.conf.json
│   └── Cargo.toml
├── .claude/                  # Claude Code configuration
└── CLAUDE.md
```

## External Integrations

None. The application is fully offline: no database server, no auth provider, no cloud sync,
no telemetry. Adding a network dependency is an architectural decision that must be discussed
before any code is written.

## Working with Claude

**Do:**

- Read the relevant code before proposing a change.
- Write the failing test first (strict TDD is on).
- Explain the _why_ of a design decision before writing the code for it.
- Ask when a requirement is ambiguous instead of assuming.
- Keep changes scoped to what was asked.

**Do not:**

- Add dependencies without stating the tradeoff first.
- Implement custom cryptographic primitives.
- Widen scope beyond the MVP list above.
- Weaken a security rule for convenience.
- Leave `unwrap()`, `console.log`, or dead code in a change.
- Commit, push, or open a PR unless explicitly asked.
