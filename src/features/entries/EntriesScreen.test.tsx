import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { vault } from '../../lib/ipc';
import { VaultLockContext } from '../vault/VaultLockContext';

import { EntriesScreen } from './EntriesScreen';

vi.mock('../../lib/ipc', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../lib/ipc')>()),
  vault: {
    list: vi.fn(),
    reveal: vi.fn(),
    add: vi.fn(),
    update: vi.fn(),
    remove: vi.fn(),
    lock: vi.fn(),
    copyPassword: vi.fn(),
    generatePassword: vi.fn(),
  },
}));

const mocked = vi.mocked(vault);

const SUMMARIES = [
  { id: 'a', site: 'github.com', username: 'octocat' },
  { id: 'b', site: 'gitlab.com', username: 'tanuki' },
];

const REVEALED = {
  id: 'a',
  site: 'github.com',
  username: 'octocat',
  password: 'hunter2',
  notes: '',
};

beforeEach(() => {
  vi.clearAllMocks();
  mocked.list.mockResolvedValue(SUMMARIES);
  mocked.reveal.mockResolvedValue(REVEALED);
  mocked.add.mockResolvedValue('c');
  mocked.update.mockResolvedValue(undefined);
  mocked.remove.mockResolvedValue(undefined);
  mocked.lock.mockResolvedValue(undefined);
  mocked.copyPassword.mockResolvedValue({ secondsUntilClear: 30, excludedFromHistory: true });
  mocked.generatePassword.mockResolvedValue({ password: 'generated', entropyBits: 130 });
});

function renderScreen(relock = vi.fn()) {
  render(
    <VaultLockContext.Provider value={relock}>
      <EntriesScreen />
    </VaultLockContext.Provider>
  );

  return relock;
}

describe('EntriesScreen', () => {
  it('lists the credentials in the vault', async () => {
    renderScreen();

    expect(await screen.findByRole('button', { name: /github\.com/ })).toBeInTheDocument();
    expect(mocked.list).toHaveBeenCalledWith('');
  });

  it('asks Rust to filter rather than filtering what it already has', async () => {
    const user = userEvent.setup();
    renderScreen();
    await screen.findByRole('button', { name: /github\.com/ });

    await user.type(screen.getByRole('searchbox', { name: 'Search' }), 'lab');

    // Searching in the interface would mean holding the whole vault to search it.
    await waitFor(() => expect(mocked.list).toHaveBeenCalledWith('lab'));
  });

  it('fetches a password only when a credential is opened', async () => {
    const user = userEvent.setup();
    renderScreen();
    await screen.findByRole('button', { name: /github\.com/ });

    expect(mocked.reveal).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: /github\.com/ }));

    expect(await screen.findByRole('heading', { name: 'github.com' })).toBeInTheDocument();
    expect(mocked.reveal).toHaveBeenCalledWith('a');
  });

  it('drops the password when the credential is closed', async () => {
    const user = userEvent.setup();
    renderScreen();
    await screen.findByRole('button', { name: /github\.com/ });
    await user.click(screen.getByRole('button', { name: /github\.com/ }));
    await screen.findByRole('heading', { name: 'github.com' });

    await user.click(screen.getByRole('button', { name: 'Close' }));

    // Reopening has to ask Rust again, which is the observable proof it was not kept.
    expect(screen.queryByLabelText('Password')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /github\.com/ }));
    await waitFor(() => expect(mocked.reveal).toHaveBeenCalledTimes(2));
  });

  it('adds a credential and refreshes the list', async () => {
    const user = userEvent.setup();
    renderScreen();
    await screen.findByRole('button', { name: 'Add credential' });

    await user.click(screen.getByRole('button', { name: 'Add credential' }));
    await user.type(screen.getByLabelText('Site'), 'example.com');
    await user.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() =>
      expect(mocked.add).toHaveBeenCalledWith({
        site: 'example.com',
        username: '',
        password: '',
        notes: '',
      })
    );
    expect(mocked.list).toHaveBeenCalledTimes(2);
  });

  it('edits a credential', async () => {
    const user = userEvent.setup();
    renderScreen();
    await screen.findByRole('button', { name: /github\.com/ });
    await user.click(screen.getByRole('button', { name: /github\.com/ }));
    await screen.findByRole('heading', { name: 'github.com' });

    await user.click(screen.getByRole('button', { name: 'Edit' }));
    await user.clear(screen.getByLabelText('Password'));
    await user.type(screen.getByLabelText('Password'), 'rotated');
    await user.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() =>
      expect(mocked.update).toHaveBeenCalledWith('a', {
        site: 'github.com',
        username: 'octocat',
        password: 'rotated',
        notes: '',
      })
    );
  });

  it('removes a credential after confirmation', async () => {
    const user = userEvent.setup();
    renderScreen();
    await screen.findByRole('button', { name: /github\.com/ });
    await user.click(screen.getByRole('button', { name: /github\.com/ }));
    await screen.findByRole('heading', { name: 'github.com' });

    await user.click(screen.getByRole('button', { name: 'Delete' }));
    await user.click(screen.getByRole('button', { name: 'Delete permanently' }));

    await waitFor(() => expect(mocked.remove).toHaveBeenCalledWith('a'));
    expect(screen.queryByLabelText('Password')).not.toBeInTheDocument();
  });

  it('copies a password without ever receiving it', async () => {
    const user = userEvent.setup();
    renderScreen();
    await screen.findByRole('button', { name: /github\.com/ });
    await user.click(screen.getByRole('button', { name: /github\.com/ }));
    await screen.findByRole('heading', { name: 'github.com' });

    await user.click(screen.getByRole('button', { name: 'Copy password' }));

    // Rust is handed the id and does the reading, writing and clearing itself. The command
    // resolves with a duration, not a password.
    await waitFor(() => expect(mocked.copyPassword).toHaveBeenCalledWith('a'));
    expect(await screen.findByRole('status')).toHaveTextContent(/cleared in 30 seconds/i);
  });

  it('forgets the clipboard notice when another credential is opened', async () => {
    const user = userEvent.setup();
    renderScreen();
    await screen.findByRole('button', { name: /github\.com/ });
    await user.click(screen.getByRole('button', { name: /github\.com/ }));
    await screen.findByRole('heading', { name: 'github.com' });
    await user.click(screen.getByRole('button', { name: 'Copy password' }));
    await screen.findByRole('status');

    mocked.reveal.mockResolvedValue({ ...REVEALED, id: 'b', site: 'gitlab.com' });
    await user.click(screen.getByRole('button', { name: /gitlab\.com/ }));
    await screen.findByRole('heading', { name: 'gitlab.com' });

    // Otherwise the notice would claim a countdown that belongs to a different password.
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });

  it('locks the vault on request', async () => {
    const user = userEvent.setup();
    const relock = renderScreen();
    await screen.findByRole('button', { name: 'Lock' });

    await user.click(screen.getByRole('button', { name: 'Lock' }));

    await waitFor(() => expect(mocked.lock).toHaveBeenCalled());
    expect(relock).toHaveBeenCalled();
  });

  it('returns to the lock screen when a command reports the vault is locked', async () => {
    const relock = vi.fn();
    // The idle timer can expire between commands without emitting an event: the session notices
    // on the next call instead. Nothing else would take the interface off this screen.
    mocked.list.mockRejectedValue({ code: 'locked', message: 'the vault is locked' });

    renderScreen(relock);

    await waitFor(() => expect(relock).toHaveBeenCalled());
  });

  it('explains a failure that is not a lock', async () => {
    mocked.list.mockRejectedValue({ code: 'storage', message: 'no' });

    renderScreen();

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The vault file could not be read or written.'
    );
  });
});
