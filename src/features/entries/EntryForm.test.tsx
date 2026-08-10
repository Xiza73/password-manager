import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { EntryForm } from './EntryForm';

function renderForm(props: Partial<React.ComponentProps<typeof EntryForm>> = {}) {
  const handlers = { onSubmit: vi.fn(), onCancel: vi.fn() };

  render(<EntryForm {...handlers} {...props} />);

  return handlers;
}

describe('EntryForm', () => {
  it('submits a complete credential', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm();

    await user.type(screen.getByLabelText('Site:'), 'github.com');
    await user.type(screen.getByLabelText('Username:'), 'octocat');
    await user.type(screen.getByLabelText('Password:'), 'hunter2');
    await user.type(screen.getByLabelText('Notes:'), 'personal account');
    await user.click(screen.getByRole('button', { name: 'Save' }));

    expect(onSubmit).toHaveBeenCalledWith({
      site: 'github.com',
      username: 'octocat',
      password: 'hunter2',
      notes: 'personal account',
    });
  });

  it('refuses a credential without a site', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm();

    await user.type(screen.getByLabelText('Password:'), 'hunter2');
    await user.click(screen.getByRole('button', { name: 'Save' }));

    // Rust refuses it too; catching it here saves a round trip to be told the same thing.
    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByRole('alert')).toHaveTextContent(/site/i);
  });

  it('accepts a credential with no username or password', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm();

    // An API key with no user, or a site plus a note, are both real entries.
    await user.type(screen.getByLabelText('Site:'), 'example.com');
    await user.click(screen.getByRole('button', { name: 'Save' }));

    expect(onSubmit).toHaveBeenCalledWith({
      site: 'example.com',
      username: '',
      password: '',
      notes: '',
    });
  });

  it('starts from an existing credential when editing', () => {
    renderForm({
      initial: { site: 'github.com', username: 'octocat', password: 'hunter2', notes: '' },
    });

    expect(screen.getByLabelText('Site:')).toHaveValue('github.com');
    expect(screen.getByLabelText('Password:')).toHaveValue('hunter2');
  });

  it('hides the password field', () => {
    renderForm();

    expect(screen.getByLabelText('Password:')).toHaveAttribute('type', 'password');
  });

  it('can show the password while typing it', async () => {
    const user = userEvent.setup();
    renderForm();

    // Typing a long generated password blind is how people end up saving a typo.
    await user.click(screen.getByRole('button', { name: 'Show password' }));

    expect(screen.getByLabelText('Password:')).toHaveAttribute('type', 'text');
  });

  it('cancels', async () => {
    const user = userEvent.setup();
    const { onCancel } = renderForm();

    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(onCancel).toHaveBeenCalled();
  });

  it('shows an error from the Rust side', () => {
    renderForm({ error: 'The vault is locked.' });

    expect(screen.getByRole('alert')).toHaveTextContent('The vault is locked.');
  });

  it('refuses a second submission while one is in flight', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm({ busy: true });

    await user.click(screen.getByRole('button', { name: 'Saving…' }));

    expect(onSubmit).not.toHaveBeenCalled();
  });
});
