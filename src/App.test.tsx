import { render, screen } from '@testing-library/react';

import { vault } from './lib/ipc';

import App from './App';

vi.mock('./lib/ipc', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./lib/ipc')>()),
  vault: {
    exists: vi.fn().mockResolvedValue(true),
    minimumMasterPasswordLength: vi.fn().mockResolvedValue(12),
    create: vi.fn(),
    unlock: vi.fn(),
    list: vi.fn().mockResolvedValue([]),
    reveal: vi.fn(),
    add: vi.fn(),
    update: vi.fn(),
    remove: vi.fn(),
    lock: vi.fn(),
  },
  onVaultLocked: vi.fn().mockResolvedValue(vi.fn()),
}));

describe('App', () => {
  it('puts the vault behind the lock screen', async () => {
    render(<App />);

    // Nothing of the vault renders until Rust says it is open, and that starts at the gate.
    expect(await screen.findByRole('button', { name: 'Unlock' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Your vault' })).not.toBeInTheDocument();
    expect(vi.mocked(vault).exists).toHaveBeenCalled();
    // Nothing was listed either: the entries screen is not even mounted while locked.
    expect(vi.mocked(vault).list).not.toHaveBeenCalled();
  });
});
