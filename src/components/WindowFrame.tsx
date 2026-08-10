import { useCallback, useState, type ReactNode } from 'react';

import { applyTheme, readStoredTheme, storeTheme, systemTheme, type Theme } from '../lib/theme';

interface WindowFrameProps {
  /** What the vault is doing, shown after the application name in the title bar. */
  subtitle: string;
  children: ReactNode;
}

/**
 * The application window: title bar, menu strip, and the panel everything else sits in.
 *
 * The minimise, maximise and close boxes and the menu labels are decoration. A Tauri window is
 * already framed by the operating system, and controls that look real but do nothing are worse
 * than no controls — so they are hidden from assistive technology rather than dressed up as
 * buttons. The theme toggle is the one control in the strip that does something.
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
          Password Manager 0.1.0 — <span className="window__subtitle">{subtitle}</span>
        </span>
        <span className="window__controls" aria-hidden="true">
          <span className="window__control window__control--minimise" />
          <span className="window__control window__control--maximise" />
          <span className="window__control window__control--close">×</span>
        </span>
      </header>

      <div className="window__menu">
        <span aria-hidden="true" className="window__menu-item window__menu-item--first">
          File
        </span>
        <span aria-hidden="true" className="window__menu-item">
          Edit
        </span>
        <span aria-hidden="true" className="window__menu-item">
          Vault
        </span>
        <span aria-hidden="true" className="window__menu-item">
          Help
        </span>
        <span className="window__menu-spacer" />
        <button type="button" className="bevel window__theme" onClick={toggle}>
          Theme: {theme === 'dark' ? 'Night' : 'Day'}
        </button>
      </div>

      <div className="window__body">{children}</div>
    </div>
  );
}
