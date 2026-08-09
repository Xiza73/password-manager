import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { EntryDetail } from './EntryDetail';

const CREDENTIAL = {
  id: 'a',
  site: 'github.com',
  username: 'octocat',
  password: 'hunter2',
  notes: 'recovery codes live here',
};

function renderDetail(props: Partial<React.ComponentProps<typeof EntryDetail>> = {}) {
  const handlers = { onEdit: vi.fn(), onDelete: vi.fn(), onClose: vi.fn(), onCopy: vi.fn() };

  render(<EntryDetail credential={CREDENTIAL} {...handlers} {...props} />);

  return handlers;
}

describe('EntryDetail', () => {
  it('shows the site and username', () => {
    renderDetail();

    expect(screen.getByRole('heading', { name: 'github.com' })).toBeInTheDocument();
    expect(screen.getByText('octocat')).toBeInTheDocument();
  });

  it('keeps the password hidden until it is asked for', () => {
    renderDetail();

    // Opening an entry must not put a password on screen for anyone walking past.
    expect(screen.queryByText('hunter2')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'password');
  });

  it('shows the password on request and hides it again', async () => {
    const user = userEvent.setup();
    renderDetail();

    await user.click(screen.getByRole('button', { name: 'Show password' }));
    expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'text');

    await user.click(screen.getByRole('button', { name: 'Hide password' }));
    expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'password');
  });

  it('keeps notes hidden too', () => {
    renderDetail();

    // Recovery codes and backup keys end up in notes, so they get the same treatment.
    expect(screen.queryByText('recovery codes live here')).not.toBeInTheDocument();
  });

  it('asks to edit', async () => {
    const user = userEvent.setup();
    const { onEdit } = renderDetail();

    await user.click(screen.getByRole('button', { name: 'Edit' }));

    expect(onEdit).toHaveBeenCalled();
  });

  it('closes', async () => {
    const user = userEvent.setup();
    const { onClose } = renderDetail();

    await user.click(screen.getByRole('button', { name: 'Close' }));

    expect(onClose).toHaveBeenCalled();
  });

  it('does not delete on the first click', async () => {
    const user = userEvent.setup();
    const { onDelete } = renderDetail();

    await user.click(screen.getByRole('button', { name: 'Delete' }));

    // Deleting a credential cannot be undone, and the vault is the only copy.
    expect(onDelete).not.toHaveBeenCalled();
    expect(screen.getByRole('alert')).toHaveTextContent(/cannot be undone/i);
  });

  it('deletes once the confirmation is clicked', async () => {
    const user = userEvent.setup();
    const { onDelete } = renderDetail();

    await user.click(screen.getByRole('button', { name: 'Delete' }));
    await user.click(screen.getByRole('button', { name: 'Delete permanently' }));

    expect(onDelete).toHaveBeenCalled();
  });

  it('lets the confirmation be called off', async () => {
    const user = userEvent.setup();
    const { onDelete } = renderDetail();

    await user.click(screen.getByRole('button', { name: 'Delete' }));
    await user.click(screen.getByRole('button', { name: 'Keep it' }));

    expect(onDelete).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: 'Delete permanently' })).not.toBeInTheDocument();
  });

  it('hides a revealed password again when a different credential is opened', async () => {
    const user = userEvent.setup();
    const props = { onEdit: vi.fn(), onDelete: vi.fn(), onClose: vi.fn(), onCopy: vi.fn() };
    const { rerender } = render(<EntryDetail credential={CREDENTIAL} {...props} />);
    await user.click(screen.getByRole('button', { name: 'Show password' }));

    rerender(
      <EntryDetail
        credential={{ ...CREDENTIAL, id: 'b', site: 'gitlab.com', password: 'other' }}
        {...props}
      />
    );

    // Otherwise clicking through a list would leave every password on screen in turn.
    expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'password');
  });

  it('asks to copy the password without ever showing it', async () => {
    const user = userEvent.setup();
    const { onCopy } = renderDetail();

    await user.click(screen.getByRole('button', { name: 'Copy password' }));

    // Copying and revealing are separate actions: the common case is paste it somewhere, and
    // that never needs it on screen.
    expect(onCopy).toHaveBeenCalled();
    expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'password');
  });

  it('says nothing about the clipboard before anything is copied', () => {
    renderDetail();

    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });

  it('says how long the clipboard will hold it', () => {
    renderDetail({ copied: { secondsUntilClear: 30, excludedFromHistory: true } });

    expect(screen.getByRole('status')).toHaveTextContent(/cleared in 30 seconds/i);
    // And that clearing is conditional, so nobody is surprised when it survives.
    expect(screen.getByRole('status')).toHaveTextContent(/unless you copy something else/i);
  });

  it('promises nothing about history when the copy was excluded from it', () => {
    renderDetail({ copied: { secondsUntilClear: 30, excludedFromHistory: true } });

    expect(screen.getByRole('status')).not.toHaveTextContent(/clipboard-history/i);
  });

  it('warns when the platform could not hide the copy from history tools', () => {
    renderDetail({ copied: { secondsUntilClear: 30, excludedFromHistory: false } });

    // On Linux there is no marker, and the timed clear does nothing about a copy a history
    // tool already wrote to disk. Saying "cleared in 30 seconds" alone would be a false
    // reassurance, which is worse than saying nothing.
    expect(screen.getByRole('status')).toHaveTextContent(/clipboard-history tools/i);
    expect(screen.getByRole('status')).toHaveTextContent(/clear it there yourself/i);
  });
});
