import { useCallback, useState, type ReactNode } from 'react';

import { applyTheme, readStoredTheme, storeTheme, systemTheme, type Theme } from '../lib/theme';

interface WindowFrameProps {
  /** What the vault is doing, shown after the application name in the title bar. */
  subtitle: string;
  children: ReactNode;
}

/**
 * The application frame: a title bar, a strip of controls, and the area everything else fills.
 *
 * The reference design put minimise, maximise and close boxes in the title bar and a
 * File / Edit / Vault / Help menu below it. Neither survived: a Tauri window is already framed by
 * the operating system, and the menus were never wired to anything. Chrome that looks like a
 * control and answers to nothing is a small lie repeated on every screen.
 */
export function WindowFrame({ subtitle, children }: WindowFrameProps) {
  const [theme, setTheme] = useState<Theme>(() => {
    const initial = readStoredTheme() ?? systemTheme();
    applyTheme(initial);
    return initial;
  });

  const toggle = useCallback(() => {
    setTheme((current) => {
      const next: Theme = current === 'dark' ? 'light' : 'dark';
      applyTheme(next);
      storeTheme(next);
      return next;
    });
  }, []);

  return (
    <div className="window">
      <header className="window__title" role="banner">
        <span className="window__icon" aria-hidden="true" />
        <span className="window__name">
          Password Manager {__APP_VERSION__} — <span className="window__subtitle">{subtitle}</span>
        </span>
      </header>

      <div className="window__strip">
        <span className="window__strip-spacer" />
        <button type="button" className="bevel window__theme" onClick={toggle}>
          Theme: {theme === 'dark' ? 'Night' : 'Day'}
        </button>
      </div>

      <div className="window__body">{children}</div>
    </div>
  );
}
