import { useState, type FormEvent } from 'react';

interface ChangeMasterPasswordFormProps {
  minimumLength: number;
  onSubmit: (current: string, next: string) => void;
  onCancel: () => void;
  error?: string;
  busy?: boolean;
}

/**
 * Re-keys the vault under a new master password.
 *
 * The current password is asked for again even though the vault is open: Rust verifies it, and a
 * change made at an unattended open vault should not be able to lock the owner out. The local
 * checks here are a courtesy — Rust enforces the same minimum — and catch the one mistake that
 * cannot be undone: a mistyped new password that re-keys the vault to something nobody knows.
 */
export function ChangeMasterPasswordForm({
  minimumLength,
  onSubmit,
  onCancel,
  error,
  busy = false,
}: ChangeMasterPasswordFormProps) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [repeated, setRepeated] = useState('');
  const [localError, setLocalError] = useState('');

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;

    // Characters, not bytes — the same count Rust applies, so the two never disagree.
    if ([...next].length < minimumLength) {
      setLocalError(`The new master password must be at least ${minimumLength} characters.`);
      return;
    }

    if (next !== repeated) {
      setLocalError('The two new master passwords do not match.');
      return;
    }

    setLocalError('');
    onSubmit(current, next);
  }

  const shown = localError || error;

  return (
    <form className="entry-form" onSubmit={handleSubmit}>
      <h2>Change master password</h2>

      <p role="note" className="warning">
        The new password replaces the old one everywhere. It cannot be recovered either, and there
        is still no backup copy of it anywhere.
      </p>

      <label htmlFor="current-master-password">Current master password:</label>
      <input
        id="current-master-password"
        type="password"
        value={current}
        onChange={(event) => setCurrent(event.target.value)}
        placeholder="••••••••"
        autoComplete="off"
        spellCheck={false}
        autoFocus
        disabled={busy}
      />

      <label htmlFor="new-master-password">New master password:</label>
      <input
        id="new-master-password"
        type="password"
        value={next}
        onChange={(event) => setNext(event.target.value)}
        placeholder="••••••••"
        autoComplete="off"
        spellCheck={false}
        disabled={busy}
        aria-describedby="new-master-password-hint"
      />
      <p id="new-master-password-hint" className="hint">
        At least {minimumLength} characters. Length is what makes it hard to guess.
      </p>

      <label htmlFor="repeat-new-master-password">Repeat new master password:</label>
      <input
        id="repeat-new-master-password"
        type="password"
        value={repeated}
        onChange={(event) => setRepeated(event.target.value)}
        placeholder="••••••••"
        autoComplete="off"
        spellCheck={false}
        disabled={busy}
      />

      {shown && (
        <p className="error" role="alert">
          {shown}
        </p>
      )}

      <footer>
        <button type="submit" disabled={busy}>
          {busy ? 'Changing…' : 'Change password'}
        </button>
        <button type="button" onClick={onCancel} disabled={busy}>
          Cancel
        </button>
      </footer>
    </form>
  );
}
