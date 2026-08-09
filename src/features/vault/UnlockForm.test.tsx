import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { UnlockForm } from './UnlockForm';

function renderForm(props: Partial<React.ComponentProps<typeof UnlockForm>> = {}) {
  const onSubmit = props.onSubmit ?? vi.fn();
  render(<UnlockForm onSubmit={onSubmit} {...props} />);
  return { onSubmit };
}

describe('UnlockForm', () => {
  it('submits the master password', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm();

    await user.type(screen.getByLabelText('Master password'), 'a master password');
    await user.click(screen.getByRole('button', { name: 'Unlock' }));

    expect(onSubmit).toHaveBeenCalledWith('a master password');
  });

  it('hides what is typed', () => {
    renderForm();

    // Not a detail: the vault is opened in rooms with other people in them.
    expect(screen.getByLabelText('Master password')).toHaveAttribute('type', 'password');
  });

  it('keeps the field out of autofill and spellcheck', () => {
    renderForm();
    const field = screen.getByLabelText('Master password');

    // Both would copy the master password somewhere this application cannot reach to erase.
    expect(field).toHaveAttribute('autocomplete', 'off');
    expect(field).toHaveAttribute('spellcheck', 'false');
  });

  it('does not submit an empty password', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm();

    await user.click(screen.getByRole('button', { name: 'Unlock' }));

    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('announces an error', () => {
    renderForm({ error: 'That master password did not open this vault.' });

    expect(screen.getByRole('alert')).toHaveTextContent(
      'That master password did not open this vault.'
    );
  });

  it('keeps what was typed after a failure so a typo can be fixed', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm({ error: 'That master password did not open this vault.' });

    await user.type(screen.getByLabelText('Master password'), 'a master password');

    // Clearing it would mean retyping a passphrase every time a finger slips.
    expect(screen.getByLabelText('Master password')).toHaveValue('a master password');
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('refuses a second submission while one is in flight', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm({ busy: true });

    await user.type(screen.getByLabelText('Master password'), 'a master password');
    await user.click(screen.getByRole('button', { name: 'Unlocking…' }));

    // Unlocking costs a fifth of a second of Argon2; without this the button invites a queue.
    expect(onSubmit).not.toHaveBeenCalled();
  });
});
