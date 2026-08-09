---
description: Build and package a release bundle of the desktop app
argument-hint: '[optional: target platform or version bump]'
allowed-tools: Read, Edit, Bash(npm run build:*), Bash(npm run tauri build:*), Bash(npm run test:*), Bash(cargo test:*), Bash(cargo clippy:*), Bash(npm run lint:*), Bash(git status:*), Bash(git diff:*), Bash(git log:*)
---

# Release Build

Target: $ARGUMENTS

This app ships as a signed desktop bundle. There is no server, so "deploy" means
**produce a distributable artifact**. Get it wrong and users install a broken vault reader.

## 1. Pre-flight

- Working tree clean? !`git status --porcelain`
- Current version in `package.json` and `src-tauri/tauri.conf.json` — these must match.
- Confirm the target platform. Tauri builds for the **host** platform only; cross-compiling
  needs a matching runner.

## 2. Gate — everything must be green

```bash
npm run test:run
cargo test --manifest-path src-tauri/Cargo.toml
npm run lint
cargo clippy --manifest-path src-tauri/Cargo.toml -- -D warnings
npx tsc --noEmit
npm audit
cargo audit --file src-tauri/Cargo.lock
```

If any of these fails, **stop**. Do not build a release on a red suite.

`cargo audit` fails only on a real vulnerability. Its `unmaintained` warnings for the GTK3 /
`glib` / `unic-*` / `proc-macro-error` crates are known and come from Tauri's own dependencies —
report a name that is not on that list, not the count.

## 3. Version bump

If a bump was requested, update **both** files (semver):

- `package.json` → `version`
- `src-tauri/tauri.conf.json` → `version`

They must stay in sync or the bundle metadata lies about what it contains.

## 4. Build

```bash
npm run tauri build
```

Artifacts land in `src-tauri/target/release/bundle/`:

- macOS → `.app` and `.dmg`
- Windows → `.msi` and `.exe` (NSIS)
- Linux → `.deb`, `.rpm`, `.AppImage`

## 5. Verify the bundle

- Confirm the artifact exists and report its path and size.
- Launch it once and confirm the vault unlock screen renders.
- Check that no dev-only surface shipped: devtools must be closed in release,
  and `src-tauri/capabilities/` must not grant permissions the app does not use.

## 6. Signing (before public distribution)

Unsigned bundles get blocked by Gatekeeper and SmartScreen.

- macOS: Developer ID certificate + notarization (`APPLE_ID`, `APPLE_TEAM_ID`,
  `APPLE_PASSWORD` env vars).
- Windows: `bundle.windows.certificateThumbprint` and `timestampUrl` in `tauri.conf.json`.

Signing credentials are never stored in the repo. If they are missing, say so and stop —
do not ship unsigned without saying it out loud.

## 7. Report

Artifact path, version, platform, signing status, and anything skipped.
Never push a tag or create a release without explicit approval.
