import { useCallback, useEffect, useState } from 'react';

import { errorMessage } from '../../lib/errorMessage';
import {
  isIpcError,
  vault,
  type CredentialDraft,
  type CopyOutcome,
  type CredentialSummary,
  type RevealedCredential,
} from '../../lib/ipc';
import { ChangeMasterPasswordForm } from '../vault/ChangeMasterPasswordForm';
import { useRelock } from '../vault/VaultLockContext';

import { EntryDetail } from './EntryDetail';
import { EntryForm } from './EntryForm';
import { EntryList } from './EntryList';

type Mode = 'browsing' | 'adding' | 'editing' | 'changing-password';

/**
 * The unlocked vault.
 *
 * The only component in the feature that talks to IPC. It holds a list of summaries — which
 * carry no secrets — and at most one revealed credential at a time, dropped as soon as it is
 * closed.
 */
export function EntriesScreen() {
  const relock = useRelock();

  const [entries, setEntries] = useState<CredentialSummary[]>([]);
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<RevealedCredential | null>(null);
  const [mode, setMode] = useState<Mode>('browsing');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState<CopyOutcome | undefined>(undefined);
  const [notice, setNotice] = useState('');
  const [minimumLength, setMinimumLength] = useState(0);

  /**
   * The single place a failed command is turned into something visible.
   *
   * A session that went idle while nothing was happening discovers it on the *next* command and
   * answers `locked` without emitting an event, so this is the only thing that would notice and
   * take the interface off a screen the Rust side has already forgotten.
   */
  const report = useCallback(
    (failure: unknown) => {
      if (isIpcError(failure) && failure.code === 'locked') {
        relock();
        return;
      }

      setError(errorMessage(failure));
    },
    [relock]
  );

  const run = useCallback(
    async <T,>(operation: () => Promise<T>): Promise<T | undefined> => {
      try {
        return await operation();
      } catch (failure) {
        report(failure);
        return undefined;
      }
    },
    [report]
  );

  const refresh = useCallback(
    async (search: string) => {
      const listed = await run(() => vault.list(search));
      if (listed) setEntries(listed);
    },
    [run]
  );

  useEffect(() => {
    let current = true;

    // Fetched once so the change-password form can state the minimum before a round trip. If it
    // fails the form still works: Rust enforces the true minimum regardless of what is shown.
    vault
      .minimumMasterPasswordLength()
      .then((minimum) => {
        if (current) setMinimumLength(minimum);
      })
      .catch(() => {});

    return () => {
      current = false;
    };
  }, []);

  useEffect(() => {
    let current = true;

    // Called without the `run` wrapper so that nothing in this effect's body touches state:
    // both outcomes are handled in callbacks instead.
    vault
      .list(query)
      .then((listed) => {
        // Typing is faster than the round trip, so an earlier query can answer after a later
        // one. Without this guard the list settles on whichever response happened to be slowest.
        if (current) setEntries(listed);
      })
      .catch((failure: unknown) => {
        if (current) report(failure);
      });

    return () => {
      current = false;
    };
  }, [query, report]);

  async function copy() {
    if (!selected) return;

    // The password is not returned: Rust reads it, writes the clipboard, and takes it back off
    // later. For the common case it never enters this process at all.
    const outcome = await run(() => vault.copyPassword(selected.id));
    if (outcome) setCopied(outcome);
  }

  async function open(id: string) {
    setError('');
    setCopied(undefined);
    setNotice('');
    const credential = await run(() => vault.reveal(id));
    if (credential) setSelected(credential);
  }

  async function changePassword(current: string, next: string) {
    setBusy(true);
    setError('');

    try {
      await vault.changeMasterPassword(current, next);
      setMode('browsing');
      setNotice('Master password changed.');
    } catch (failure) {
      if (isIpcError(failure) && failure.code === 'locked') {
        relock();
        return;
      }

      // In this flow `unauthentic` means the current password field was wrong, not the vault:
      // the generic unlock wording would send the user looking in the wrong place.
      setError(
        isIpcError(failure) && failure.code === 'unauthentic'
          ? 'The current password is not correct.'
          : errorMessage(failure)
      );
    } finally {
      setBusy(false);
    }
  }

  function close() {
    // Dropping the state is what makes reopening ask Rust again, which is the point: the
    // interface holds one secret for as long as it is being looked at, and no longer.
    setSelected(null);
    setCopied(undefined);
    setMode('browsing');
  }

  async function save(draft: CredentialDraft) {
    setBusy(true);
    setError('');

    const done =
      mode === 'editing' && selected
        ? await run(() => vault.update(selected.id, draft))
        : await run(() => vault.add(draft));

    setBusy(false);
    if (done === undefined && error) return;

    close();
    await refresh(query);
  }

  async function remove() {
    if (!selected) return;

    setBusy(true);
    await run(() => vault.remove(selected.id));
    setBusy(false);

    close();
    await refresh(query);
  }

  async function lock() {
    await run(() => vault.lock());
    relock();
  }

  if (mode === 'changing-password') {
    return (
      <div className="vault">
        <ChangeMasterPasswordForm
          minimumLength={minimumLength}
          onSubmit={(current, next) => void changePassword(current, next)}
          onCancel={() => {
            setError('');
            setMode('browsing');
          }}
          error={error}
          busy={busy}
        />
      </div>
    );
  }

  if (mode === 'adding' || mode === 'editing') {
    return (
      <div className="vault">
        <EntryForm
          onSubmit={(draft) => void save(draft)}
          onCancel={() => setMode('browsing')}
          initial={
            mode === 'editing' && selected
              ? {
                  site: selected.site,
                  username: selected.username,
                  password: selected.password,
                  notes: selected.notes,
                }
              : undefined
          }
          error={error}
          busy={busy}
        />
      </div>
    );
  }

  return (
    <div className="vault">
      {/* The window title bar carries the name visually; this keeps a heading in the document
          outline for anyone navigating by structure. */}
      <h1 className="visually-hidden">Your vault</h1>

      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}

      {notice && (
        <p className="hint" role="status">
          {notice}
        </p>
      )}

      <div className="vault__body">
        <EntryList
          entries={entries}
          query={query}
          onQueryChange={setQuery}
          onSelect={(id) => void open(id)}
          onAdd={() => {
            setSelected(null);
            setNotice('');
            setMode('adding');
          }}
          selectedId={selected?.id}
        />

        {selected && (
          <EntryDetail
            credential={selected}
            onEdit={() => setMode('editing')}
            onDelete={() => void remove()}
            onClose={close}
            onCopy={() => void copy()}
            copied={copied}
          />
        )}
      </div>

      <div className="window__status">
        <span>{selected ? selected.site : 'Vault open. Select an entry.'}</span>
        <span>
          {entries.length} {entries.length === 1 ? 'entry' : 'entries'}
        </span>
        <button
          type="button"
          className="bevel"
          onClick={() => {
            setError('');
            setNotice('');
            setMode('changing-password');
          }}
        >
          Change password
        </button>
        <button type="button" className="bevel window__status-lock" onClick={() => void lock()}>
          Lock
        </button>
      </div>
    </div>
  );
}
