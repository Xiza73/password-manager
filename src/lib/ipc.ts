/**
 * The single boundary between the WebView and the Rust core.
 *
 * Components never call `invoke` directly. Every command gets a typed wrapper here so the
 * contract lives in one place and a change on the Rust side breaks the build instead of
 * failing silently at runtime.
 */
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

/** Codes the Rust side sends. Anything else arrives as `unknown`. */
export type IpcErrorCode =
  | 'locked'
  | 'no_vault'
  | 'vault_exists'
  | 'weak_password'
  | 'not_found'
  | 'site_required'
  | 'unauthentic'
  | 'not_a_vault'
  | 'unsupported_version'
  | 'malformed'
  | 'storage'
  | 'clipboard'
  | 'no_character_classes'
  | 'length_out_of_range'
  | 'random_unavailable'
  | 'internal'
  | 'unknown';

/** Error shape returned by every command. Never carries secret material. */
export interface IpcError {
  code: IpcErrorCode;
  message: string;
}

export function isIpcError(value: unknown): value is IpcError {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as IpcError).code === 'string' &&
    typeof (value as IpcError).message === 'string'
  );
}

/**
 * Calls a Tauri command and normalises whatever it rejects with into an `IpcError`.
 *
 * Rust may reject with a plain string (a panic bubbling up) or with our structured error.
 * Callers should only ever have to handle the structured form.
 */
export async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (raw) {
    if (isIpcError(raw)) throw raw;
    throw { code: 'unknown', message: String(raw) } satisfies IpcError;
  }
}

/**
 * A credential without its secrets.
 *
 * This is what listing and searching return, and it is deliberately all the interface holds for
 * the bulk of the vault. There is no password field to forget to clear.
 */
export interface CredentialSummary {
  id: string;
  site: string;
  username: string;
}

/** One credential, with its secrets. Fetched one at a time, never for a whole list. */
export interface RevealedCredential extends CredentialSummary {
  password: string;
  notes: string;
}

/** What the interface sends when creating or editing a credential. */
export interface CredentialDraft {
  site: string;
  username: string;
  password: string;
  notes: string;
}

export const vault = {
  /** Length the Rust side enforces, so the form can say so before submitting. */
  minimumMasterPasswordLength: () => call<number>('minimum_master_password_length'),

  exists: () => call<boolean>('vault_exists'),

  /**
   * Whether the vault is open, according to Rust.
   *
   * Asked rather than remembered: a lock that only the interface knows about is a lock anyone
   * can undo from the developer tools.
   */
  isUnlocked: () => call<boolean>('is_unlocked'),

  create: (password: string) => call<void>('create_vault', { password }),

  /**
   * Opens the vault. Succeeds even when the vault turns out to be older than the last one opened
   * on this machine — the answer says so rather than refusing.
   */
  unlock: (password: string) => call<Unlocked>('unlock', { password }),

  lock: () => call<void>('lock'),

  /**
   * Deletes the vault and returns the app to first-run.
   *
   * The only way back in when the master password is lost: it recovers nothing and discards
   * everything. There is no recovery by design — the key derives from the password and nothing
   * else — so this is the honest alternative, not a workaround.
   */
  reset: () => call<void>('reset_vault'),

  list: (query?: string) => call<CredentialSummary[]>('list_entries', { query: query ?? null }),

  reveal: (id: string) => call<RevealedCredential>('reveal_entry', { id }),

  add: (draft: CredentialDraft) => call<string>('add_entry', { draft }),

  update: (id: string, draft: CredentialDraft) => call<void>('update_entry', { id, draft }),

  remove: (id: string) => call<void>('remove_entry', { id }),

  generatePassword: (options: GeneratorOptions) =>
    call<GeneratedPassword>('generate_password', { options }),

  /**
   * Copies a credential's password to the clipboard.
   *
   * The password is never returned: Rust reads it, writes it, and takes it back off the
   * clipboard later.
   */
  copyPassword: (id: string) => call<CopyOutcome>('copy_password', { id }),
};

export interface Unlocked {
  /**
   * The vault carries a lower save counter than one already opened here: a stale copy from a
   * sync folder, a half-restored backup, or a file someone swapped.
   */
  rolledBack: boolean;
}

export interface CopyOutcome {
  secondsUntilClear: number;
  /**
   * Whether the platform could mark the copy so clipboard-history tools ignore it.
   *
   * False on Linux, which has no equivalent marker. Reported rather than assumed so the
   * interface can say what actually happened instead of promising what it cannot deliver.
   */
  excludedFromHistory: boolean;
}

export interface GeneratorOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  avoidAmbiguous: boolean;
}

export interface GeneratedPassword {
  password: string;
  /** Bits of guessing the password is worth — a number, not a verdict. */
  entropyBits: number;
}

/** Fired when the idle timer closes the vault, so the interface can drop what it is showing. */
export const VAULT_LOCKED_EVENT = 'vault-locked';

export function onVaultLocked(handler: () => void): Promise<UnlistenFn> {
  return listen(VAULT_LOCKED_EVENT, () => handler());
}
