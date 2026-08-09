import { useCallback, useEffect, useState, type ReactNode } from 'react';

import { errorMessage } from '../../lib/errorMessage';
import { onVaultLocked, vault } from '../../lib/ipc';

import { CreateVaultForm } from './CreateVaultForm';
import { UnlockForm } from './UnlockForm';
import { VaultLockContext } from './VaultLockContext';

type Screen = 'checking' | 'create' | 'unlock' | 'open';

interface VaultGateProps {
  children: ReactNode;
}

/**
 * Decides whether the vault needs creating, unlocking, or is already open, and renders nothing
 * of its contents until Rust says it is open.
 *
 * This is the only component in the feature that talks to IPC. The forms below it take props and
 * hand back a password, which keeps the thing that can fail in one place.
 */
export function VaultGate({ children }: VaultGateProps) {
  const [screen, setScreen] = useState<Screen>('checking');
  const [minimumLength, setMinimumLength] = useState(0);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let current = true;

    Promise.all([vault.exists(), vault.minimumMasterPasswordLength()])
      .then(([exists, minimum]) => {
        if (!current) return;
        setMinimumLength(minimum);
        setScreen(exists ? 'unlock' : 'create');
      })
      .catch((failure) => {
        if (!current) return;
        setError(errorMessage(failure));
        setScreen('unlock');
      });

    return () => {
      current = false;
    };
  }, []);

  const relock = useCallback(() => {
    // Rust has already dropped the key. Showing the vault a moment longer would be showing
    // something that no longer exists.
    setScreen('unlock');
    setError('');
  }, []);

  useEffect(() => {
    let current = true;
    // The promise may resolve after this effect is torn down, so the unsubscribe is called
    // straight away in that case rather than leaked.
    let stop: (() => void) | undefined;

    onVaultLocked(relock).then((unlisten) => {
      if (current) stop = unlisten;
      else unlisten();
    });

    return () => {
      current = false;
      stop?.();
    };
  }, [relock]);

  const attempt = useCallback(async (operation: () => Promise<void>) => {
    setBusy(true);
    setError('');

    try {
      await operation();
      setScreen('open');
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setBusy(false);
    }
  }, []);

  if (screen === 'checking') return <p className="panel">Looking for your vault…</p>;

  if (screen === 'open') {
    return <VaultLockContext.Provider value={relock}>{children}</VaultLockContext.Provider>;
  }

  if (screen === 'create') {
    return (
      <CreateVaultForm
        minimumLength={minimumLength}
        onSubmit={(password) => void attempt(() => vault.create(password))}
        error={error}
        busy={busy}
      />
    );
  }

  return (
    <UnlockForm
      onSubmit={(password) => void attempt(() => vault.unlock(password))}
      error={error}
      busy={busy}
    />
  );
}
