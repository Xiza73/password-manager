import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { WindowFrame } from './WindowFrame';

beforeEach(() => {
  localStorage.clear();
  document.documentElement.removeAttribute('data-theme');
});

describe('WindowFrame', () => {
  it('renders what it wraps', () => {
    render(
      <WindowFrame subtitle="vault locked">
        <p>contents</p>
      </WindowFrame>
    );

    expect(screen.getByText('contents')).toBeInTheDocument();
  });

  it('names the window and its current state', () => {
    render(
      <WindowFrame subtitle="vault locked">
        <p>contents</p>
      </WindowFrame>
    );

    expect(screen.getByRole('banner')).toHaveTextContent(/Password Manager/);
    expect(screen.getByRole('banner')).toHaveTextContent('vault locked');
  });

  it('shows the version the build was made from', () => {
    render(
      <WindowFrame subtitle="vault locked">
        <p>contents</p>
      </WindowFrame>
    );

    // Injected from package.json at build time. Hardcoding it here is how the title bar ends up
    // claiming a version the manifests stopped agreeing with two releases ago.
    expect(screen.getByRole('banner')).toHaveTextContent(
      new RegExp(`Password Manager ${__APP_VERSION__}\\b`)
    );
    expect(__APP_VERSION__).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it('carries no control that does nothing', () => {
    render(
      <WindowFrame subtitle="vault locked">
        <p>contents</p>
      </WindowFrame>
    );

    // The reference had minimise, maximise and close boxes plus a File / Edit / Vault / Help
    // menu, all decoration. The operating system already frames the window and the menus were
    // never wired to anything, so they are gone rather than pretending.
    expect(within(screen.getByRole('banner')).queryAllByRole('button')).toHaveLength(0);
    expect(screen.queryByText(/^(File|Edit|Vault|Help)$/)).not.toBeInTheDocument();

    // The theme toggle is the one control the frame owns, and it works.
    expect(screen.getByRole('button', { name: /theme/i })).toBeInTheDocument();
  });

  it('toggles between the two palettes', async () => {
    const user = userEvent.setup();
    render(
      <WindowFrame subtitle="vault locked">
        <p>contents</p>
      </WindowFrame>
    );

    const toggle = screen.getByRole('button', { name: /theme/i });
    const before = document.documentElement.getAttribute('data-theme');

    await user.click(toggle);

    expect(document.documentElement.getAttribute('data-theme')).not.toBe(before);
  });

  it('remembers the choice', async () => {
    const user = userEvent.setup();
    render(
      <WindowFrame subtitle="vault locked">
        <p>contents</p>
      </WindowFrame>
    );

    await user.click(screen.getByRole('button', { name: /theme/i }));

    expect(localStorage.getItem('password-manager.theme')).toBe(
      document.documentElement.getAttribute('data-theme')
    );
  });

  it('starts from a stored choice rather than the system', () => {
    localStorage.setItem('password-manager.theme', 'light');

    render(
      <WindowFrame subtitle="vault locked">
        <p>contents</p>
      </WindowFrame>
    );

    expect(document.documentElement).toHaveAttribute('data-theme', 'light');
  });
});
