import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { EntryList } from './EntryList';

const ENTRIES = [
  { id: 'a', site: 'github.com', username: 'octocat' },
  { id: 'b', site: 'gitlab.com', username: 'tanuki' },
];

function renderList(props: Partial<React.ComponentProps<typeof EntryList>> = {}) {
  const handlers = {
    onQueryChange: vi.fn(),
    onSelect: vi.fn(),
    onAdd: vi.fn(),
  };

  render(<EntryList entries={ENTRIES} query="" {...handlers} {...props} />);

  return handlers;
}

describe('EntryList', () => {
  it('lists every credential with its site and username', () => {
    renderList();

    expect(screen.getByRole('button', { name: /github\.com/ })).toHaveTextContent('octocat');
    expect(screen.getByRole('button', { name: /gitlab\.com/ })).toBeInTheDocument();
  });

  it('selects a credential', async () => {
    const user = userEvent.setup();
    const { onSelect } = renderList();

    await user.click(screen.getByRole('button', { name: /github\.com/ }));

    expect(onSelect).toHaveBeenCalledWith('a');
  });

  it('reports each keystroke in the search box', async () => {
    const user = userEvent.setup();
    const { onQueryChange } = renderList({ query: 'gi' });

    await user.type(screen.getByRole('searchbox', { name: 'Search:' }), 't');

    // The input is controlled and this component keeps no state, so it reports the new value
    // and lets the container decide. Accumulating a query is the container's test, not this one.
    expect(onQueryChange).toHaveBeenCalledWith('git');
  });

  it('asks to add a credential', async () => {
    const user = userEvent.setup();
    const { onAdd } = renderList();

    await user.click(screen.getByRole('button', { name: 'New entry' }));

    expect(onAdd).toHaveBeenCalled();
  });

  it('invites a first credential when the vault is empty', () => {
    renderList({ entries: [] });

    expect(screen.getByText(/no credentials yet/i)).toBeInTheDocument();
  });

  it('says so when a search matches nothing', () => {
    renderList({ entries: [], query: 'nothing' });

    // A different message from an empty vault: one means "add your first", the other means
    // "your entry is there, your search is wrong".
    expect(screen.getByText(/nothing matches/i)).toBeInTheDocument();
  });

  it('marks the selected credential for assistive technology', () => {
    renderList({ selectedId: 'b' });

    expect(screen.getByRole('button', { name: /gitlab\.com/ })).toHaveAttribute(
      'aria-current',
      'true'
    );
    expect(screen.getByRole('button', { name: /github\.com/ })).not.toHaveAttribute('aria-current');
  });
});
