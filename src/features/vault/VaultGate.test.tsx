import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { vault, onVaultLocked } from '../../lib/ipc';

import { VaultGate } from './VaultGate';

vi.mock('../../lib/ipc', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../lib/ipc')>()),
  vault: {
    exists: vi.fn(),
    minimumMasterPasswordLength: vi.fn(),
    create: vi.fn(),
    unlock: vi.fn(),
  },
  onVaultLocked: vi.fn(),
}));

const mocked = vi.mocked(vault);
const onVaultLockedMock = vi.mocked(onVaultLocked);
// Typed with an explicit signature: a bare `vi.fn()` is not assignable to `UnlistenFn`.
let unlisten: ReturnType<typeof vi.fn<() => void>>;

beforeEach(() => {
  vi.clearAllMocks();
  unlisten = vi.fn<() => void>();
  onVaultLockedMock.mockResolvedValue(unlisten);
  mocked.minimumMasterPasswordLength.mockResolvedValue(12);
  mocked.exists.mockResolvedValue(true);
  mocked.unlock.mockResolvedValue(undefined);
  mocked.create.mockResolvedValue(undefined);
});

function renderGate() {
  render(
    <VaultGate>
      <p>the vault is open</p>
    </VaultGate>
  );
}

describe('VaultGate', () => {
  it('asks to unlock when a vault already exists', async () => {
    renderGate();

    expect(await screen.findByRole('button', { name: 'Unlock' })).toBeInTheDocument();
  });

  it('offers to create one when there is no vault', async () => {
    mocked.exists.mockResolvedValue(false);

    renderGate();

    expect(await screen.findByRole('button', { name: 'Create vault' })).toBeInTheDocument();
  });

  it('shows nothing of the vault until it is open', async () => {
    renderGate();
    await screen.findByRole('button', { name: 'Unlock' });

    expect(screen.queryByText('the vault is open')).not.toBeInTheDocument();
  });

  it('reveals the vault after a successful unlock', async () => {
    const user = userEvent.setup();
    renderGate();
    await screen.findByRole('button', { name: 'Unlock' });

    await user.type(screen.getByLabelText('Master password'), 'a master password');
    await user.click(screen.getByRole('button', { name: 'Unlock' }));

    expect(await screen.findByText('the vault is open')).toBeInTheDocument();
    expect(mocked.unlock).toHaveBeenCalledWith('a master password');
  });

  it('stays closed and explains when the password is wrong', async () => {
    const user = userEvent.setup();
    mocked.unlock.mockRejectedValue({ code: 'unauthentic', message: 'no' });
    renderGate();
    await screen.findByRole('button', { name: 'Unlock' });

    await user.type(screen.getByLabelText('Master password'), 'wrong');
    await user.click(screen.getByRole('button', { name: 'Unlock' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'That master password did not open this vault.'
    );
    expect(screen.queryByText('the vault is open')).not.toBeInTheDocument();
  });

  it('opens the vault straight after creating it', async () => {
    const user = userEvent.setup();
    mocked.exists.mockResolvedValue(false);
    renderGate();
    await screen.findByRole('button', { name: 'Create vault' });

    await user.type(screen.getByLabelText('Master password'), 'a long enough password');
    await user.type(screen.getByLabelText('Repeat master password'), 'a long enough password');
    await user.click(screen.getByRole('button', { name: 'Create vault' }));

    expect(await screen.findByText('the vault is open')).toBeInTheDocument();
  });

  it('passes the minimum length from Rust to the form', async () => {
    mocked.exists.mockResolvedValue(false);
    mocked.minimumMasterPasswordLength.mockResolvedValue(16);

    renderGate();

    expect(await screen.findByText(/at least 16 characters/i)).toBeInTheDocument();
  });

  it('goes back to the lock screen when the idle timer fires', async () => {
    const user = userEvent.setup();
    renderGate();
    await screen.findByRole('button', { name: 'Unlock' });
    await user.type(screen.getByLabelText('Master password'), 'a master password');
    await user.click(screen.getByRole('button', { name: 'Unlock' }));
    await screen.findByText('the vault is open');

    // The Rust side has already dropped the key; the interface must stop showing what it was
    // showing rather than wait to be told again by a failing command.
    onVaultLockedMock.mock.calls[0][0]();

    expect(await screen.findByRole('button', { name: 'Unlock' })).toBeInTheDocument();
    expect(screen.queryByText('the vault is open')).not.toBeInTheDocument();
  });

  it('stops listening for the lock event when it goes away', async () => {
    const { unmount } = render(
      <VaultGate>
        <p>the vault is open</p>
      </VaultGate>
    );
    await screen.findByRole('button', { name: 'Unlock' });

    unmount();

    await waitFor(() => expect(unlisten).toHaveBeenCalled());
  });
});
