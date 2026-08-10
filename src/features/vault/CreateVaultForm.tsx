import { useState, type FormEvent } from 'react';

interface CreateVaultFormProps {
  minimumLength: number;
  onSubmit: (password: string) => void;
  error?: string;
  busy?: boolean;
}

/**
 * Sets the master password for a brand new vault.
 *
 * The checks here are a courtesy, not the rule — Rust enforces the minimum and would refuse
 * anything shorter. Doing them locally saves a fifth of a second of key derivation to be told
 * something the form already knew.
 */
export function CreateVaultForm({
  minimumLength,
  onSubmit,
  error,
  busy = false,
}: CreateVaultFormProps) {
  const [password, setPassword] = useState('');
  const [repeated, setRepeated] = useState('');
  const [localError, setLocalError] = useState('');

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;

    // Characters, not bytes — the same count the Rust side applies, so the two never disagree
    // about whether a password in a non-Latin script is long enough.
    if ([...password].length < minimumLength) {
      setLocalError(`The master password must be at least ${minimumLength} characters.`);
      return;
    }

    // A typo here seals the vault with a password nobody knows, and nothing opens it afterwards.
    if (password !== repeated) {
      setLocalError('The two master passwords do not match.');
      return;
    }

    setLocalError('');
    onSubmit(password);
  }

  const shown = localError || error;

  return (
    <div className="gate">
      <div className="gate__intro">
        <h1>Create your vault</h1>
        <p>Choose the one password that opens everything else.</p>
      </div>

      <form className="panel" onSubmit={handleSubmit}>
        <p role="note" className="warning">
          Your master password cannot be recovered. Nobody, including this application, can open the
          vault without it — there is no reset and no backup copy of it anywhere.
        </p>

        <label htmlFor="master-password">Master password:</label>
        <input
          id="master-password"
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          placeholder="••••••••"
          autoComplete="off"
          spellCheck={false}
          autoFocus
          disabled={busy}
          aria-describedby="master-password-hint"
        />
        <p id="master-password-hint" className="hint">
          At least {minimumLength} characters. Length is what makes it hard to guess, so a few
          unrelated words beat a short password with symbols in it.
        </p>

        <label htmlFor="repeat-master-password">Repeat master password:</label>
        <input
          id="repeat-master-password"
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

        <div className="panel__actions">
          <button type="submit" className="bevel" disabled={busy}>
            {busy ? 'Creating…' : 'Create vault'}
          </button>
        </div>
      </form>
    </div>
  );
}
