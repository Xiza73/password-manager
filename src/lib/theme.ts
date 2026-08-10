/**
 * Which of the two palettes the interface is painted in.
 *
 * The choice is stored, but its absence is meaningful: it means "follow the operating system".
 * A theme preference is the one thing in this application that is not a secret, so it is the one
 * thing that may live in `localStorage`.
 */
export type Theme = 'light' | 'dark';

export const THEME_STORAGE_KEY = 'password-manager.theme';

function isTheme(value: unknown): value is Theme {
  return value === 'light' || value === 'dark';
}

/** The stored choice, or `undefined` when the system should decide. */
export function readStoredTheme(): Theme | undefined {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    return isTheme(stored) ? stored : undefined;
  } catch {
    // Storage can be unavailable or full. Falling back to the system preference is a better
    // outcome than failing to render.
    return undefined;
  }
}

export function storeTheme(theme: Theme): void {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // The choice will not survive a restart. Not worth interrupting anyone over.
  }
}

/** Stamps the choice on the document so the stylesheet can key off it. */
export function applyTheme(theme: Theme): void {
  document.documentElement.setAttribute('data-theme', theme);
}

/** What the operating system is asking for right now. */
export function systemTheme(): Theme {
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}
