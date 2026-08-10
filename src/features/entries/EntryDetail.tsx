import { useState } from 'react';

import type { CopyOutcome, RevealedCredential } from '../../lib/ipc';

interface EntryDetailProps {
  credential: RevealedCredential;
  onEdit: () => void;
  onDelete: () => void;
  onClose: () => void;
  onCopy: () => void;
  /** What happened to the last copy, once one has been made. */
  copied?: CopyOutcome;
}

/**
 * One credential, with its secrets available but not on display.
 *
 * Opening an entry is not the same as wanting its password on screen — the two are separate
 * actions here, because the first one happens in rooms with other people in them.
 */
export function EntryDetail({
  credential,
  onEdit,
  onDelete,
  onClose,
  onCopy,
  copied,
}: EntryDetailProps) {
  // Both flags remember *which* credential they apply to, rather than being reset when the
  // credential changes. An effect that resets them would leave a window — one render — where a
  // password from the previous entry is still on screen under the new entry's name. Deriving
  // them makes that impossible instead of unlikely.
  const [revealedFor, setRevealedFor] = useState<string | null>(null);
  const [confirmingFor, setConfirmingFor] = useState<string | null>(null);

  const revealed = revealedFor === credential.id;
  const confirming = confirmingFor === credential.id;

  return (
    <section className="entry-detail">
      <header>
        <h2>{credential.site}</h2>
        <button type="button" onClick={onClose}>
          Close
        </button>
      </header>

      <p className="entry-detail__username">{credential.username || '—'}</p>

      <label htmlFor="detail-password">Password:</label>
      <div className="entry-detail__secret">
        <input
          id="detail-password"
          type={revealed ? 'text' : 'password'}
          value={credential.password}
          readOnly
          autoComplete="off"
          spellCheck={false}
        />
        <button type="button" onClick={onCopy}>
          Copy password
        </button>
        <button type="button" onClick={() => setRevealedFor(revealed ? null : credential.id)}>
          {revealed ? 'Hide password' : 'Show password'}
        </button>
      </div>

      {copied && (
        <p className={copied.excludedFromHistory ? 'hint' : 'warning'} role="status">
          Copied. The clipboard will be cleared in {copied.secondsUntilClear} seconds, unless you
          copy something else first.
          {!copied.excludedFromHistory &&
            ' This system cannot hide the copy from clipboard-history tools, so anything' +
              ' recording your clipboard has kept it. Clear it there yourself.'}
        </p>
      )}

      <label htmlFor="detail-notes">Notes:</label>
      <textarea
        id="detail-notes"
        // Recovery codes and backup keys end up in notes, so they are masked with the password
        // rather than treated as ordinary text.
        value={revealed ? credential.notes : credential.notes.replace(/./gs, '•')}
        readOnly
        rows={3}
      />

      <footer>
        <button type="button" onClick={onEdit}>
          Edit
        </button>

        {confirming ? (
          <>
            <p className="error" role="alert">
              Deleting this credential cannot be undone. This vault is the only copy.
            </p>
            <button type="button" className="danger" onClick={onDelete}>
              Delete permanently
            </button>
            <button type="button" onClick={() => setConfirmingFor(null)}>
              Keep it
            </button>
          </>
        ) : (
          <button type="button" className="danger" onClick={() => setConfirmingFor(credential.id)}>
            Delete
          </button>
        )}
      </footer>
    </section>
  );
}
