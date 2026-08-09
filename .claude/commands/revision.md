---
description: Review uncommitted changes for correctness, security and project conventions
argument-hint: '[optional: path or feature to focus on]'
allowed-tools: Read, Grep, Glob, Bash(git diff:*), Bash(git status:*), Bash(git log:*)
---

# Code Review

Review the current uncommitted changes. Focus area (optional): $ARGUMENTS

## Gather context

- Current diff: !`git diff HEAD`
- Untracked files: !`git status --porcelain`

## Review checklist

Go through each dimension and report only real findings — no filler.

### 1. Correctness

- Does the change do what it claims? Any off-by-one, wrong branch, or unhandled case?
- Are error paths handled, or does the code assume the happy path?
- Rust: any `unwrap()` / `expect()` reachable from a `#[tauri::command]`? That is a crash.

### 2. Security (this is a password manager — hold the bar high)

- Any plaintext secret, master password, or derived key that gets logged, printed,
  serialized, or written to disk?
- Is key material zeroized on drop?
- Any hand-rolled cryptography instead of a vetted crate?
- Does new IPC surface widen what the WebView can reach? Check `src-tauri/capabilities/`.

### 3. Conventions (see CLAUDE.md)

- TypeScript: `any`, unexplained `@ts-ignore`, barrel files?
- Components calling `invoke` directly instead of going through `src/lib/ipc.ts`?
- Tauri v1 APIs sneaking in (`@tauri-apps/api/tauri`, `allowlist`, `emit_all`)?
- Container/presentational split respected?

### 4. Tests

- Strict TDD is on: does every behaviour change have a test?
- Crypto changes: are wrong-password and tampered-ciphertext cases covered?
- Do tests assert behaviour, or implementation details?

### 5. Scope

- Does the change stay inside what was asked, or did it grow?
- Dead code, leftover `console.log`, commented-out blocks?

## Output

For each finding: file and line, what is wrong, **why** it matters, and the concrete fix.
Order by severity. If the change is clean, say so plainly — do not invent problems.
