import { useState, type FormEvent } from 'react';

import type { CredentialDraft } from '../../lib/ipc';

import { PasswordGenerator } from './PasswordGenerator';

interface EntryFormProps {
  onSubmit: (draft: CredentialDraft) => void;
  onCancel: () => void;
  initial?: CredentialDraft;
  error?: string;
  busy?: boolean;
}

const EMPTY: CredentialDraft = { site: '', username: '', password: '', notes: '' };

/**
 * Creates or edits one credential.
 *
 * The only required field is the site, matching the rule Rust enforces: an API key with no user,
 * or a site with nothing but a note, are both entries worth keeping.
 */
export function EntryForm({ onSubmit, onCancel, initial, error, busy = false }: EntryFormProps) {
  const [draft, setDraft] = useState<CredentialDraft>(initial ?? EMPTY);
  const [revealed, setRevealed] = useState(false);
  const [localError, setLocalError] = useState('');

  function update(field: keyof CredentialDraft, value: string) {
    setDraft((current) => ({ ...current, [field]: value }));
  }

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;

    if (draft.site.trim().length === 0) {
      // Rust refuses this too. Catching it here saves a round trip to be told the same thing.
      setLocalError('A credential needs a site.');
      return;
    }

    setLocalError('');
    onSubmit({ ...draft, site: draft.site.trim() });
  }

  const shown = localError || error;

  return (
    <form className="entry-form" onSubmit={handleSubmit}>
      <h2>{initial ? 'Edit credential' : 'New credential'}</h2>

      <label htmlFor="entry-site">Site:</label>
      <input
        id="entry-site"
        value={draft.site}
        onChange={(event) => update('site', event.target.value)}
        autoComplete="off"
        autoFocus
        disabled={busy}
      />

      <label htmlFor="entry-username">Username:</label>
      <input
        id="entry-username"
        value={draft.username}
        onChange={(event) => update('username', event.target.value)}
        autoComplete="off"
        disabled={busy}
      />

      <label htmlFor="entry-password">Password:</label>
      <div className="entry-form__secret">
        <input
          id="entry-password"
          type={revealed ? 'text' : 'password'}
          value={draft.password}
          onChange={(event) => update('password', event.target.value)}
          autoComplete="off"
          spellCheck={false}
          disabled={busy}
        />
        <button type="button" onClick={() => setRevealed((state) => !state)} disabled={busy}>
          {revealed ? 'Hide password' : 'Show password'}
        </button>
      </div>

      <PasswordGenerator
        onUse={(password) => {
          update('password', password);
          // Shown straight away: a generated password that is never read is a password nobody
          // can check was saved correctly.
          setRevealed(true);
        }}
      />

      <label htmlFor="entry-notes">Notes:</label>
      <textarea
        id="entry-notes"
        value={draft.notes}
        onChange={(event) => update('notes', event.target.value)}
        rows={3}
        disabled={busy}
      />

      {shown && (
        <p className="error" role="alert">
          {shown}
        </p>
      )}

      <footer>
        <button type="submit" disabled={busy}>
          {busy ? 'Saving…' : 'Save'}
        </button>
        <button type="button" onClick={onCancel} disabled={busy}>
          Cancel
        </button>
      </footer>
    </form>
  );
}
