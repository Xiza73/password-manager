import { useState, type FormEvent } from 'react';

interface UnlockFormProps {
  onSubmit: (password: string) => void;
  error?: string;
  busy?: boolean;
}

/**
 * Asks for the master password. Holds no state beyond what is being typed and reports nothing
 * about whether the vault is open — that answer belongs to Rust.
 */
export function UnlockForm({ onSubmit, error, busy = false }: UnlockFormProps) {
  const [password, setPassword] = useState('');

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
    </div>
  );
}
