import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { vault } from '../../lib/ipc';

import { PasswordGenerator } from './PasswordGenerator';

vi.mock('../../lib/ipc', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../lib/ipc')>()),
  vault: { generatePassword: vi.fn() },
}));

const mocked = vi.mocked(vault);

beforeEach(() => {
  vi.clearAllMocks();
  mocked.generatePassword.mockResolvedValue({ password: 'GeNeRaTeD-1234', entropyBits: 131.4 });
});

function renderGenerator(onUse = vi.fn()) {
  render(<PasswordGenerator onUse={onUse} />);
  return onUse;
}

describe('PasswordGenerator', () => {
  it('asks Rust to generate, with every class on by default', async () => {
    const user = userEvent.setup();
    renderGenerator();

    await user.click(screen.getByRole('button', { name: 'Generate' }));

    await waitFor(() =>
      expect(mocked.generatePassword).toHaveBeenCalledWith({
        length: 20,
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: true,
        avoidAmbiguous: false,
      })
    );
  });

  it('generates in Rust rather than in the interface', async () => {
    const user = userEvent.setup();
    renderGenerator();

    await user.click(screen.getByRole('button', { name: 'Generate' }));
    await screen.findByDisplayValue('GeNeRaTeD-1234');

    // `Math.random()` is not a cryptographic source, and a generator written here would be
    // reaching for it. The only correct place for this is next to the system RNG.
    expect(mocked.generatePassword).toHaveBeenCalled();
  });

  it('passes the chosen options through', async () => {
    const user = userEvent.setup();
    renderGenerator();

    await user.click(screen.getByLabelText('Symbols'));
    await user.click(screen.getByLabelText('Avoid look-alike characters'));
    await user.clear(screen.getByLabelText('Length:'));
    await user.type(screen.getByLabelText('Length:'), '32');
    await user.click(screen.getByRole('button', { name: 'Generate' }));

    await waitFor(() =>
      expect(mocked.generatePassword).toHaveBeenCalledWith(
        expect.objectContaining({ length: 32, symbols: false, avoidAmbiguous: true })
      )
    );
  });

  it('reports entropy as a number rather than a verdict', async () => {
    const user = userEvent.setup();
    renderGenerator();

    await user.click(screen.getByRole('button', { name: 'Generate' }));

    // "Strong" is a claim the arithmetic does not support and it hides what excluding
    // look-alike characters costs.
    expect(await screen.findByText(/131 bits of entropy/i)).toBeInTheDocument();
  });

  it('hands the generated password to the form', async () => {
    const user = userEvent.setup();
    const onUse = renderGenerator();
    await user.click(screen.getByRole('button', { name: 'Generate' }));
    await screen.findByDisplayValue('GeNeRaTeD-1234');

    await user.click(screen.getByRole('button', { name: 'Use this password' }));

    expect(onUse).toHaveBeenCalledWith('GeNeRaTeD-1234');
  });

  it('offers nothing to use before anything is generated', () => {
    renderGenerator();

    expect(screen.queryByRole('button', { name: 'Use this password' })).not.toBeInTheDocument();
  });

  it('explains a refusal from Rust', async () => {
    const user = userEvent.setup();
    mocked.generatePassword.mockRejectedValue({ code: 'no_character_classes', message: 'no' });
    renderGenerator();

    await user.click(screen.getByRole('button', { name: 'Generate' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Choose at least one kind of character.'
    );
  });
});
