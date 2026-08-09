---
name: deploy
description: Build, version, sign and distribute the Tauri v2 desktop bundle. Trigger when preparing a release, bumping the version, producing a .dmg/.msi/.AppImage, configuring code signing or notarization, or setting up the release CI workflow.
---

# Release and Distribution

There is no server to deploy to. Shipping this app means producing a **signed, installable
bundle** for each target platform.

## Version discipline

Two files carry the version and they must never drift:

- `package.json` → `version`
- `src-tauri/tauri.conf.json` → `version`

Semver: breaking vault format change → major. New feature → minor. Fix → patch.

A vault format change deserves special care: an older build must refuse a newer vault with a
clear message rather than corrupting it. Version the vault header.

## Build

```bash
npm run tauri build              # release bundle for the host platform
npm run tauri build -- --debug   # debug bundle, for reproducing a release-only issue
```

Output: `src-tauri/target/release/bundle/`

| Platform | Artifacts                   | Notes                                                  |
| -------- | --------------------------- | ------------------------------------------------------ |
| macOS    | `.app`, `.dmg`              | WKWebView. Never ship `open_devtools()` — private API. |
| Windows  | `.msi`, `.exe` (NSIS)       | WebView2 is preinstalled on Windows 11.                |
| Linux    | `.deb`, `.rpm`, `.AppImage` | webkitgtk must be installed on the host.               |

Tauri builds for the **host** platform only. Multi-platform releases need a CI matrix
(macos-latest, windows-latest, ubuntu-22.04).

## Signing

Unsigned means blocked. Gatekeeper on macOS, SmartScreen on Windows.

**macOS** — Developer ID Application certificate plus notarization. Environment:
`APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`,
`APPLE_PASSWORD`, `APPLE_TEAM_ID`.

**Windows** — configured under the **top-level** `bundle` key (not `tauri.bundle`, that is v1):

```json
{
  "bundle": {
    "windows": {
      "certificateThumbprint": "A1B2...",
      "digestAlgorithm": "sha256",
      "timestampUrl": "http://timestamp.comodoca.com"
    }
  }
}
```

An EV certificate earns SmartScreen trust immediately; an OV certificate builds reputation
over time.

Signing secrets live in the CI secret store. Never in the repo, never in a config file,
never in a shell history.

## Pre-release gate

Do not build a release on a red suite:

```bash
npm run test:run
cargo test --manifest-path src-tauri/Cargo.toml
npm run lint
cargo clippy --manifest-path src-tauri/Cargo.toml -- -D warnings
npx tsc --noEmit
npm audit
cargo audit --file src-tauri/Cargo.lock   # cargo install cargo-audit --locked
```

`cargo audit` exits non-zero only on a real vulnerability. It also reports `unmaintained` and
`unsound` warnings, and this project carries a known set of them: the GTK3 bindings and `glib`
that Tauri pulls in for its Linux backend, the `unic-*` crates behind `urlpattern`, and
`proc-macro-error`. None is in the cryptographic path, and none is fixable here — they move when
Tauri moves. Read the list rather than counting it: a new name appearing is the signal.

Then verify the bundle itself: install it clean, unlock a vault, confirm the capability set in
`src-tauri/capabilities/` grants nothing the app does not use.

## Release checklist

1. Suites and linters green.
2. Version bumped in both files.
3. CHANGELOG updated.
4. Bundle built and manually smoke-tested.
5. Bundle signed and (macOS) notarized.
6. Tag `vX.Y.Z` created — **only with explicit approval**.
7. Artifacts and checksums attached to the release.

Publish checksums. Users of a password manager have every reason to verify what they installed.

## Never

- Ship unsigned without saying so explicitly.
- Push a tag or publish a release without approval.
- Commit signing credentials or certificates.
- Bundle a debug build as a release.
