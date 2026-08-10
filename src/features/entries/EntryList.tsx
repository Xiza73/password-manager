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
 * The vault's index, drawn as a column list.
 *
 * Everything here comes from `CredentialSummary`, which has no password field — so this
 * component can render every entry in the vault without a single secret passing through it.
 * The reference design showed passwords inline in a fourth column; that is exactly what this
 * type exists to prevent, so the password lives in the detail panel instead.
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
      <div className="vault__toolbar">
        <button type="button" className="bevel" onClick={onAdd}>
          New entry
        </button>
        <span className="vault__toolbar-spacer" />
        <label htmlFor="entry-search">Search:</label>
        <input
          id="entry-search"
          type="search"
          value={query}
          onChange={(event) => onQueryChange(event.target.value)}
          autoComplete="off"
          spellCheck={false}
        />
      </div>

      <div className="entry-list__well">
        <div className="entry-list__head" aria-hidden="true">
          <span>Service</span>
          <span>User</span>
        </div>

        {entries.length === 0 ? (
          <p className="entry-list__empty">
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
                  <span className="entry-list__username">{entry.username || '—'}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
