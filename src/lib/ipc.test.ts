import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

import { call, isIpcError, onVaultLocked, vault, VAULT_LOCKED_EVENT } from './ipc';

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(),
}));

const invokeMock = vi.mocked(invoke);
const listenMock = vi.mocked(listen);

beforeEach(() => {
  vi.clearAllMocks();
  invokeMock.mockResolvedValue(undefined);
});

describe('call', () => {
  it('returns the command result', async () => {
    invokeMock.mockResolvedValue({ entries: 3 });

    await expect(call('list_entries')).resolves.toEqual({ entries: 3 });
    expect(invokeMock).toHaveBeenCalledWith('list_entries', undefined);
  });

  it('forwards a structured error unchanged', async () => {
    invokeMock.mockRejectedValue({ code: 'locked', message: 'the vault is locked' });

    await expect(call('list_entries')).rejects.toEqual({
      code: 'locked',
      message: 'the vault is locked',
    });
  });

  it('wraps an unstructured rejection so callers always get an IpcError', async () => {
    invokeMock.mockRejectedValue('something exploded');

    await expect(call('list_entries')).rejects.toEqual({
      code: 'unknown',
      message: 'something exploded',
    });
  });
});

describe('isIpcError', () => {
  it.each([null, undefined, 'oops', 42, {}, { code: 'x' }])('rejects %o', (value) => {
    expect(isIpcError(value)).toBe(false);
  });

  it('accepts a well-formed error', () => {
    expect(isIpcError({ code: 'locked', message: 'the vault is locked' })).toBe(true);
  });
});

describe('vault', () => {
  // The command names are the contract with Rust. A rename on either side has to break here,
  // because nothing else in the interface mentions them.
  it.each([
    [
      'minimumMasterPasswordLength',
      () => vault.minimumMasterPasswordLength(),
      'minimum_master_password_length',
      undefined,
    ],
    ['exists', () => vault.exists(), 'vault_exists', undefined],
    ['isUnlocked', () => vault.isUnlocked(), 'is_unlocked', undefined],
    [
      'create',
      () => vault.create('a master password'),
      'create_vault',
      { password: 'a master password' },
    ],
    [
      'unlock',
      () => vault.unlock('a master password'),
      'unlock',
      { password: 'a master password' },
    ],
    ['lock', () => vault.lock(), 'lock', undefined],
    ['reveal', () => vault.reveal('an-id'), 'reveal_entry', { id: 'an-id' }],
    ['remove', () => vault.remove('an-id'), 'remove_entry', { id: 'an-id' }],
  ])('%s calls the right command', async (_name, operation, command, args) => {
    await operation();

    expect(invokeMock).toHaveBeenCalledWith(command, args);
  });

  it('sends null rather than omitting an absent search query', async () => {
    await vault.list();

    expect(invokeMock).toHaveBeenCalledWith('list_entries', { query: null });
  });

  it('passes a search query through', async () => {
    await vault.list('github');

    expect(invokeMock).toHaveBeenCalledWith('list_entries', { query: 'github' });
  });

  it('sends a draft when adding', async () => {
    const draft = { site: 'github.com', username: 'octocat', password: 'hunter2', notes: '' };

    await vault.add(draft);

    expect(invokeMock).toHaveBeenCalledWith('add_entry', { draft });
  });

  it('sends the id alongside the draft when updating', async () => {
    const draft = { site: 'github.com', username: 'octocat', password: 'rotated', notes: '' };

    await vault.update('an-id', draft);

    expect(invokeMock).toHaveBeenCalledWith('update_entry', { id: 'an-id', draft });
  });
});

describe('onVaultLocked', () => {
  it('subscribes to the lock event', async () => {
    const unlisten = vi.fn();
    listenMock.mockResolvedValue(unlisten);
    const handler = vi.fn();

    await expect(onVaultLocked(handler)).resolves.toBe(unlisten);
    expect(listenMock).toHaveBeenCalledWith(VAULT_LOCKED_EVENT, expect.any(Function));
  });

  it('calls the handler when the event fires', async () => {
    const handler = vi.fn();
    listenMock.mockResolvedValue(vi.fn());
    await onVaultLocked(handler);

    // The listener receives a Tauri event object; the handler must not have to care.
    listenMock.mock.calls[0][1]({ event: VAULT_LOCKED_EVENT, id: 1, payload: null });

    expect(handler).toHaveBeenCalledWith();
  });
});
