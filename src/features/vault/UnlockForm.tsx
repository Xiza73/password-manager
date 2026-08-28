import { useState, type FormEvent } from 'react';

interface UnlockFormProps {
  onSubmit: (password: string) => void;
  /** Deletes the vault and starts over. The only answer to a lost master password. */
  onReset: () => void;
  error?: string;
  busy?: boolean;
}

/**
 * Asks for the master password. Holds no state beyond what is being typed and reports nothing
 * about whether the vault is open — that answer belongs to Rust.
 */
export function UnlockForm({ onSubmit, onReset, error, busy = false }: UnlockFormProps) {
  const [password, setPassword] = useState('');
  // The destructive path is deliberately two steps: reveal, then confirm. Deleting every
  // credential must never be a stray click away from the unlock button.
  const [confirmingReset, setConfirmingReset] = useState(false);

  function handleSubmit(event: FormEvent) {
    event.preventDefault();

    // Unlocking costs a fifth of a second of Argon2. Without this guard an impatient second
    // click queues a second derivation for no reason.
    if (busy || password.length === 0) return;

    onSubmit(password);
  }

  return (
    <div className="gate">
      <div className="gate__intro">
        <h1>Enter your master password</h1>
        <p>It is the only password you have to remember. Nothing else opens this vault.</p>
      </div>

      <form className="panel" onSubmit={handleSubmit}>
        <label htmlFor="master-password">Master password:</label>
        <input
          id="master-password"
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          placeholder="••••••••"
          // Autofill and spellcheck both copy what is typed somewhere this application cannot
          // reach to erase it.
          autoComplete="off"
          spellCheck={false}
          autoFocus
          disabled={busy}
        />

        <p className="hint gate__note">
          <span className="gate__tick" aria-hidden="true">
            ✓
          </span>
          Locks itself after five minutes of inactivity
        </p>

        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}

        <div className="panel__actions">
          <button type="submit" className="bevel" disabled={busy}>
            {busy ? 'Unlocking…' : 'Unlock'}
          </button>
        </div>
      </form>

      <div className="gate__recovery">
        {confirmingReset ? (
          <div className="panel gate__reset" role="group" aria-label="Delete this vault">
            <p className="warning">
              There is no way to recover a forgotten master password — it is never stored, so
              nothing can look it up. The only way forward is to delete this vault and start a new
              one. Every credential in it goes with it, and this cannot be undone.
            </p>
            <div className="panel__actions">
              <button type="button" className="bevel danger" onClick={onReset} disabled={busy}>
                {busy ? 'Deleting…' : 'Delete vault and start over'}
              </button>
              <button
                type="button"
                className="bevel"
                onClick={() => setConfirmingReset(false)}
                disabled={busy}
              >
                Keep the vault
              </button>
            </div>
          </div>
        ) : (
          <button
            type="button"
            className="gate__recovery-link"
            onClick={() => setConfirmingReset(true)}
          >
            Forgot your master password?
          </button>
        )}
      </div>
    </div>
  );
}
