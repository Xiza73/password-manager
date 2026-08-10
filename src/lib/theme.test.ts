import { applyTheme, readStoredTheme, storeTheme, THEME_STORAGE_KEY } from './theme';

beforeEach(() => {
  localStorage.clear();
  document.documentElement.removeAttribute('data-theme');
});

describe('readStoredTheme', () => {
  it('has no opinion before anything was chosen', () => {
    // Absent means "follow the system", not "light". Defaulting to a colour scheme the user
    // never picked is how an application ends up glowing white at two in the morning.
    expect(readStoredTheme()).toBeUndefined();
  });

  it('returns what was stored', () => {
    localStorage.setItem(THEME_STORAGE_KEY, 'light');

    expect(readStoredTheme()).toBe('light');
  });

  it('ignores a value it does not recognise', () => {
    localStorage.setItem(THEME_STORAGE_KEY, 'neon');

    expect(readStoredTheme()).toBeUndefined();
  });
});

describe('storeTheme', () => {
  it('remembers a choice across sessions', () => {
    storeTheme('dark');

    expect(readStoredTheme()).toBe('dark');
  });

  it('survives storage being unavailable', () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('quota');
    });

    // A theme preference is not worth crashing the vault over.
    expect(() => storeTheme('dark')).not.toThrow();

    setItem.mockRestore();
  });
});

describe('applyTheme', () => {
  it('stamps the choice where CSS can read it', () => {
    applyTheme('light');

    expect(document.documentElement).toHaveAttribute('data-theme', 'light');
  });

  it('replaces a previous choice rather than adding to it', () => {
    applyTheme('light');
    applyTheme('dark');

    expect(document.documentElement).toHaveAttribute('data-theme', 'dark');
  });
});
