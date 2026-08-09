import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { CreateVaultForm } from './CreateVaultForm';

const LONG_ENOUGH = 'a long enough master password';

function renderForm(props: Partial<React.ComponentProps<typeof CreateVaultForm>> = {}) {
  const onSubmit = props.onSubmit ?? vi.fn();
  render(<CreateVaultForm minimumLength={12} onSubmit={onSubmit} {...props} />);
  return { onSubmit };
}

async function fill(user: ReturnType<typeof userEvent.setup>, password: string, repeat = password) {
  await user.type(screen.getByLabelText('Master password'), password);
  await user.type(screen.getByLabelText('Repeat master password'), repeat);
}

describe('CreateVaultForm', () => {
  it('creates the vault when both fields agree', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm();

    await fill(user, LONG_ENOUGH);
    await user.click(screen.getByRole('button', { name: 'Create vault' }));

    expect(onSubmit).toHaveBeenCalledWith(LONG_ENOUGH);
  });

  it('warns that a forgotten master password cannot be recovered', () => {
    renderForm();

    // The single most important thing to say on this screen. There is no reset link, and the
    // moment to learn that is before the vault holds anything.
    expect(screen.getByRole('note')).toHaveTextContent(/cannot be recovered/i);
  });

  it('states the minimum length before anything is typed', () => {
    renderForm({ minimumLength: 12 });

    expect(screen.getByText(/at least 12 characters/i)).toBeInTheDocument();
  });

  it('refuses a password shorter than the minimum', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm({ minimumLength: 12 });

    await fill(user, 'short');
    await user.click(screen.getByRole('button', { name: 'Create vault' }));

    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByRole('alert')).toHaveTextContent(/at least 12 characters/i);
  });

  it('refuses when the two fields disagree', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm();

    await fill(user, LONG_ENOUGH, 'a different long password');
    await user.click(screen.getByRole('button', { name: 'Create vault' }));

    // A typo here seals the vault with a password nobody knows, and nothing can open it after.
    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByRole('alert')).toHaveTextContent(/do not match/i);
  });

  it('counts characters rather than bytes, like the Rust side does', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm({ minimumLength: 12 });

    // Twelve characters, more than twelve bytes.
    await fill(user, 'contraseñaña');
    await user.click(screen.getByRole('button', { name: 'Create vault' }));

    expect(onSubmit).toHaveBeenCalledWith('contraseñaña');
  });

  it('hides both fields', () => {
    renderForm();

    expect(screen.getByLabelText('Master password')).toHaveAttribute('type', 'password');
    expect(screen.getByLabelText('Repeat master password')).toHaveAttribute('type', 'password');
  });

  it('shows an error from the Rust side', () => {
    renderForm({ error: 'A vault already exists on this computer.' });

    expect(screen.getByRole('alert')).toHaveTextContent('A vault already exists on this computer.');
  });

  it('refuses a second submission while one is in flight', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm({ busy: true });

    await user.click(screen.getByRole('button', { name: 'Creating…' }));

    expect(onSubmit).not.toHaveBeenCalled();
  });
});
