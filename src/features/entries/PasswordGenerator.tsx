import { useState } from 'react';

import { errorMessage } from '../../lib/errorMessage';
import { vault, type GeneratorOptions } from '../../lib/ipc';

interface PasswordGeneratorProps {
  onUse: (password: string) => void;
}

const DEFAULTS: GeneratorOptions = {
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: false,
};

const CLASSES: { key: keyof GeneratorOptions; label: string }[] = [
  { key: 'lowercase', label: 'Lowercase' },
  { key: 'uppercase', label: 'Uppercase' },
  { key: 'digits', label: 'Digits' },
  { key: 'symbols', label: 'Symbols' },
];

/**
 * Draws a password from the system's random number generator.
 *
 * The drawing happens in Rust, not here. A generator written in the interface would reach for
 * `Math.random()`, which is not a cryptographic source and produces passwords that look random
 * to a person and are not random to anyone attacking them.
 */
export function PasswordGenerator({ onUse }: PasswordGeneratorProps) {
  const [options, setOptions] = useState<GeneratorOptions>(DEFAULTS);
  const [generated, setGenerated] = useState<{ password: string; entropyBits: number } | null>(
    null
  );
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  function toggle(key: keyof GeneratorOptions) {
    setOptions((current) => ({ ...current, [key]: !current[key] }));
  }

  async function generate() {
    setBusy(true);
    setError('');

    try {
      setGenerated(await vault.generatePassword(options));
    } catch (failure) {
      setGenerated(null);
      setError(errorMessage(failure));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="generator">
      <h3>Generate a password</h3>

      <div className="generator__options">
        <label htmlFor="generator-length">Length:</label>
        <input
          id="generator-length"
          type="number"
          min={8}
          max={128}
          value={options.length}
          onChange={(event) =>
            setOptions((current) => ({ ...current, length: Number(event.target.value) }))
          }
          disabled={busy}
        />

        {CLASSES.map(({ key, label }) => (
          <label key={key} className="generator__toggle">
            <input
              type="checkbox"
              checked={Boolean(options[key])}
              onChange={() => toggle(key)}
              disabled={busy}
            />
            {label}
          </label>
        ))}

        <label className="generator__toggle">
          <input
            type="checkbox"
            checked={options.avoidAmbiguous}
            onChange={() => toggle('avoidAmbiguous')}
            disabled={busy}
          />
          Avoid look-alike characters
        </label>
      </div>

      <button type="button" onClick={() => void generate()} disabled={busy}>
        {busy ? 'Generating…' : 'Generate'}
      </button>

      {generated && (
        <>
          <label className="visually-hidden" htmlFor="generated-password">
            Generated password
          </label>
          <input id="generated-password" value={generated.password} readOnly spellCheck={false} />
          <p className="hint">
            {/* A number, not a verdict. "Strong" would be a claim the arithmetic does not
                support, and it would hide what excluding look-alike characters costs. */}
            {Math.round(generated.entropyBits)} bits of entropy
          </p>
          <button type="button" onClick={() => onUse(generated.password)}>
            Use this password
          </button>
        </>
      )}

      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}
