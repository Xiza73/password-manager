import { createContext, useContext } from 'react';

/**
 * Sends the interface back to the lock screen.
 *
 * Needed because the idle timeout has two ways of firing. The background timer emits an event,
 * which [`VaultGate`] listens for — but a session that went idle while nothing was happening
 * discovers it on the *next* command instead, and answers with a `locked` error and no event.
 * Without this, the interface would sit there showing a list the Rust side has already forgotten.
 */
export const VaultLockContext = createContext<() => void>(() => {});

export function useRelock(): () => void {
  return useContext(VaultLockContext);
}
