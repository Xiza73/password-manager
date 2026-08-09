import { isIpcError } from './ipc';

const FALLBACK = 'Something went wrong. Please try again.';

const MESSAGES: Record<string, string> = {
  // Deliberately does not say "wrong password". A failed unlock and a tampered vault are one
  // answer all the way up from the cipher, and the wording keeps that promise instead of
  // guessing which one happened.
  unauthentic: 'That master password did not open this vault.',
  no_vault: 'There is no vault on this computer yet.',
  vault_exists: 'A vault already exists on this computer.',
  not_a_vault: 'That file is not a vault.',
  malformed: 'This vault file is damaged. Restore it from a backup.',
  unsupported_version:
    'This vault was written by a newer version of the application. Update to open it.',
  storage: 'The vault file could not be read or written.',
  locked: 'The vault is locked.',
  site_required: 'A credential needs a site.',
  not_found: 'That credential is no longer in the vault.',
  clipboard: 'The password could not be copied to the clipboard.',
  no_character_classes: 'Choose at least one kind of character.',
  length_out_of_range: 'That length is outside what the generator supports.',
  random_unavailable: 'The system random number generator is unavailable.',
};

/**
 * Turns whatever a command rejected with into something worth showing a person.
 *
 * Messages are written here rather than forwarded from Rust, with one exception: a Rust message
 * could one day carry a path or a value, and nothing on this side would notice. Only
 * `weak_password` is passed through, because it is assembled from a constant and is the only one
 * that has to state a number the interface does not otherwise know.
 */
export function errorMessage(error: unknown): string {
  if (!isIpcError(error)) return FALLBACK;

  if (error.code === 'weak_password') {
    return `${error.message.charAt(0).toUpperCase()}${error.message.slice(1)}.`;
  }

  return MESSAGES[error.code] ?? FALLBACK;
}
