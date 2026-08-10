import { render, screen } from '@testing-library/react';
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

  it('hides the decorative chrome from assistive technology', () => {
    render(
      <WindowFrame subtitle="vault locked">
        <p>contents</p>
      </WindowFrame>
    );

    // The minimise, maximise and close boxes are skin: the real window controls belong to the
    // operating system. Exposing them as buttons would promise something they do not do.
    expect(screen.queryByRole('button', { name: /close|minimi|maximi/i })).not.toBeInTheDocument();
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
