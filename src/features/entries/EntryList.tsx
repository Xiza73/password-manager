import type { CredentialSummary } from '../../lib/ipc';

interface EntryListProps {
  entries: CredentialSummary[];
  query: string;
  onQueryChange: (query: string) => void;
  onSelect: (id: string) => void;
  onAdd: () => void;
  selectedId?: string;
}

/**
 * The vault's index.
 *
 * Everything here comes from `CredentialSummary`, which has no password field — so this
 * component can render every entry in the vault without a single secret passing through it.
 */
export function EntryList({
  entries,
  query,
  onQueryChange,
  onSelect,
  onAdd,
  selectedId,
}: EntryListProps) {
  return (
    <div className="entry-list">
      <div className="entry-list__controls">
        <label className="visually-hidden" htmlFor="entry-search">
          Search
        </label>
        <input
          id="entry-search"
          type="search"
          value={query}
          onChange={(event) => onQueryChange(event.target.value)}
          placeholder="Search by site or username"
          autoComplete="off"
          spellCheck={false}
        />
        <button type="button" onClick={onAdd}>
          Add credential
        </button>
      </div>

      {entries.length === 0 ? (
        <p className="hint">
          {query.trim().length > 0
            ? 'Nothing matches that search.'
            : 'No credentials yet. Add your first one.'}
        </p>
      ) : (
        <ul className="entry-list__items">
          {entries.map((entry) => (
            <li key={entry.id}>
              <button
                type="button"
                onClick={() => onSelect(entry.id)}
                aria-current={entry.id === selectedId ? 'true' : undefined}
              >
                <span className="entry-list__site">{entry.site}</span>
                <span className="entry-list__username">{entry.username}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
