import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { ChangeMasterPasswordForm } from './ChangeMasterPasswordForm';

function renderForm(props: Partial<React.ComponentProps<typeof ChangeMasterPasswordForm>> = {}) {
  const onSubmit = props.onSubmit ?? vi.fn();
  const onCancel = props.onCancel ?? vi.fn();
  render(
    <ChangeMasterPasswordForm
      minimumLength={12}
      onSubmit={onSubmit}
      onCancel={onCancel}
      {...props}
    />
  );
  return { onSubmit, onCancel };
}

describe('ChangeMasterPasswordForm', () => {
  it('submits the current and the new password', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm();

    await user.type(screen.getByLabelText('Current master password:'), 'the old password');
    await user.type(screen.getByLabelText('New master password:'), 'a brand new password');
    await user.type(screen.getByLabelText('Repeat new master password:'), 'a brand new password');
    await user.click(screen.getByRole('button', { name: 'Change password' }));

    expect(onSubmit).toHaveBeenCalledWith('the old password', 'a brand new password');
  });

  it('hides every field', () => {
    renderForm();

    // A password manager should not put a master password on screen, current or new.
    expect(screen.getByLabelText('Current master password:')).toHaveAttribute('type', 'password');
    expect(screen.getByLabelText('New master password:')).toHaveAttribute('type', 'password');
    expect(screen.getByLabelText('Repeat new master password:')).toHaveAttribute(
      'type',
      'password'
    );
  });

  it('refuses a new password shorter than the minimum', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm({ minimumLength: 12 });

    await user.type(screen.getByLabelText('Current master password:'), 'the old password');
    await user.type(screen.getByLabelText('New master password:'), 'short');
    await user.type(screen.getByLabelText('Repeat new master password:'), 'short');
    await user.click(screen.getByRole('button', { name: 'Change password' }));

    expect(screen.getByRole('alert')).toHaveTextContent(/at least 12 characters/i);
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('refuses a new password that does not match its repeat', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm();

    await user.type(screen.getByLabelText('Current master password:'), 'the old password');
    await user.type(screen.getByLabelText('New master password:'), 'a brand new password');
    await user.type(screen.getByLabelText('Repeat new master password:'), 'a different password');
    await user.click(screen.getByRole('button', { name: 'Change password' }));

    // A typo here re-keys the vault to a password nobody knows.
    expect(screen.getByRole('alert')).toHaveTextContent(/do not match/i);
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('announces an error from the backend', () => {
    renderForm({ error: 'The current password is not correct.' });

    expect(screen.getByRole('alert')).toHaveTextContent('The current password is not correct.');
  });

  it('can be cancelled', async () => {
    const user = userEvent.setup();
    const { onCancel } = renderForm();

    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('does not submit while one change is already in flight', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm({ busy: true });

    await user.click(screen.getByRole('button', { name: 'Changing…' }));

    expect(onSubmit).not.toHaveBeenCalled();
  });
});
