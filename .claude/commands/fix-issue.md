---
description: Work a bug from reproduction to verified fix, test-first
argument-hint: '<issue number, or a description of the bug>'
allowed-tools: Read, Edit, Write, Grep, Glob, Bash(npm run test:*), Bash(cargo test:*), Bash(npm run lint:*), Bash(cargo clippy:*), Bash(git diff:*), Bash(git status:*)
---

# Fix Issue

Target: $ARGUMENTS

Follow these steps in order. Do not skip ahead to the fix.

## 1. Understand

Read the issue or description. State in one or two sentences what the observed behaviour is
and what the expected behaviour is. If those two are not clear, **stop and ask** — do not guess.

## 2. Locate

Find the code responsible. Search by symptom, not by hunch. Note the relevant files and
the boundary the bug lives on (UI, IPC layer, Rust command, crypto core, persistence).

## 3. Diagnose

Explain the **root cause** — the mechanism, not the symptom. "It returns the wrong value" is a
symptom. "The auto-lock timer is reset on every render because the effect has no dependency
array" is a root cause.

If you cannot explain the mechanism, you have not found the bug yet. Keep digging.

## 4. Reproduce with a failing test

Strict TDD. Write a test that fails for exactly this reason, in the right layer:

- UI behaviour → Vitest + React Testing Library
- IPC contract or core logic → `cargo test` in `src-tauri/`

Run it. Confirm it fails, and that it fails for the right reason.

## 5. Fix

Make the smallest change that makes the test pass. Do not refactor surrounding code in the
same pass — note it for later instead.

## 6. Verify

```bash
npm run test:run
cargo test --manifest-path src-tauri/Cargo.toml
npm run lint
cargo clippy --manifest-path src-tauri/Cargo.toml -- -D warnings
```

All four must pass. Report the actual output — if something fails, say so.

## 7. Report

- Root cause, in one paragraph.
- What changed and why.
- Proposed Conventional Commit message (`fix(scope): ...`).

Do not commit unless asked.
