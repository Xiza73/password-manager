---
name: security-review
description: Audit code that touches secrets, cryptography, vault storage, or the Tauri IPC boundary. Trigger when reviewing or writing key derivation, encryption, master password handling, clipboard access, auto-lock, capability grants, or any change under src-tauri/crypto or src-tauri/vault.
---

# Security Review

This is a password manager. A subtle mistake here does not produce a bug report — it produces
a silent breach. Review with that weight.

## Threat model

The vault file is assumed to be readable by an attacker (stolen laptop, backup, sync folder).
Everything rests on: the master password is unknown, the KDF is expensive, and the AEAD detects
tampering. Anything that weakens one of those three is a critical finding.

Out of scope: a compromised OS, a keylogger, or a malicious kernel. Do not spend effort there.

## Audit checklist

### Key derivation

- Argon2id, not PBKDF2 or bcrypt, and not a raw hash.
- Parameters are explicit and tuned (memory cost, time cost, parallelism) — never library defaults
  chosen by accident.
- Salt is unique per vault, generated from a CSPRNG, and stored alongside the ciphertext.
- The derived key is never written to disk.

### Encryption

- AES-256-GCM or ChaCha20-Poly1305. An AEAD, always — never a bare cipher.
- Nonce is never reused with the same key. Verify how it is generated and incremented.
- Authentication failure is treated as a hard error, never as "decrypt anyway".
- No custom construction, no XOR, no home-made padding.

### Secret lifetime

- Key material and plaintext passwords are wrapped in `Zeroizing`, or implement `Drop` with
  zeroization.
- No secret crosses `Debug`, `Display`, `Serialize`, `println!`, `dbg!`, `tracing`, or a panic
  message. Check derived impls too — `#[derive(Debug)]` on a struct holding a key leaks it.
- No secret lands in an error string returned across IPC.
- Clipboard writes have a timed clear, and the timer survives window blur.

### Randomness

- CSPRNG only (`rand::rngs::OsRng`, `getrandom`). Never `rand::random` with a seeded PRNG,
  never `Math.random()` for anything security-relevant — including the password generator.
- The generator's character-set selection must be unbiased (no modulo bias).

### IPC boundary

- Every `#[tauri::command]` validates its input. The WebView is untrusted.
- Commands return `Result` with a serializable error that reveals nothing sensitive.
- `src-tauri/capabilities/*.json` grants the minimum. Flag `fs:default`, `shell:*`, or any
  broad grant the app does not actually need.
- The master password crosses IPC once, at unlock, and is not retained in JS state afterwards.

### Frontend

- No secret in `localStorage`, `sessionStorage`, IndexedDB, a URL, or a React DevTools-visible
  global.
- No `dangerouslySetInnerHTML` with entry data — notes fields are attacker-influenced.
- Auto-lock actually clears in-memory state, not just the visible route.

### Dependencies

- New crypto dependency? Check it is maintained and widely used. Report `cargo audit` findings.

## Output format

For each finding:

1. **Severity** — critical / high / medium / low
2. **Location** — file and line
3. **What** — the concrete flaw
4. **Why it matters** — the attack it enables, in plain terms
5. **Fix** — the specific change

Rank by severity. Do not pad the list. If the code is sound, say it is sound and explain what
you verified — a review that always finds something is a review nobody trusts.
