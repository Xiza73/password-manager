import { errorMessage } from './errorMessage';

describe('errorMessage', () => {
  it('explains a failed unlock without claiming why it failed', () => {
    const message = errorMessage({
      code: 'unauthentic',
      message: 'the vault could not be unlocked',
    });

    // A wrong password and a tampered file are one answer all the way up the stack, and the
    // wording has to stay true to that rather than guess on the user's behalf.
    expect(message).toBe('That master password did not open this vault.');
  });

  it('passes a weak-password message through, because it carries the minimum', () => {
    const message = errorMessage({
      code: 'weak_password',
      message: 'the master password must be at least 12 characters',
    });

    expect(message).toBe('The master password must be at least 12 characters.');
  });

  it.each([
    ['no_vault', 'There is no vault on this computer yet.'],
    ['vault_exists', 'A vault already exists on this computer.'],
    ['not_a_vault', 'That file is not a vault.'],
    ['malformed', 'This vault file is damaged. Restore it from a backup.'],
    ['storage', 'The vault file could not be read or written.'],
    ['locked', 'The vault is locked.'],
  ])('explains %s', (code, expected) => {
    expect(errorMessage({ code, message: 'ignored' })).toBe(expected);
  });

  it('tells the user to update when the vault is from a newer version', () => {
    const message = errorMessage({ code: 'unsupported_version', message: 'ignored' });

    expect(message).toContain('newer version');
  });

  it.each([null, undefined, 'a bare string', { code: 'something_new', message: 'x' }])(
    'falls back for %o',
    (value) => {
      expect(errorMessage(value)).toBe('Something went wrong. Please try again.');
    }
  );

  it('never repeats a message that could carry a secret', () => {
    // Only `weak_password` is passed through, and it is the one message built from a constant.
    const message = errorMessage({ code: 'internal', message: 'hunter2 leaked in here' });

    expect(message).not.toContain('hunter2');
  });
});
