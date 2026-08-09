//! Generating passwords worth using.
//!
//! Two things make a generator correct, and both are easy to get subtly wrong. The randomness
//! has to come from the operating system, and the sampling has to be unbiased — a naive
//! `random() % alphabet.len()` favours the first characters of the alphabet and quietly costs
//! entropy that nobody ever notices missing.

use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use rand::seq::IndexedRandom;
use rand::TryRng;
use serde::{Deserialize, Serialize};

use crate::secret::SecretString;

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";

/// Chosen to be widely accepted by sites that restrict symbols, and to avoid characters that
/// break shell quoting badly enough that people paste them wrong.
pub const SYMBOLS: &str = "!#$%&()*+-./:;<=>?@[]^_{|}~";

/// Characters that are hard to tell apart in the fonts people actually read passwords in.
pub const AMBIGUOUS: &str = "0O1lI";

/// Shortest password this generator will produce.
///
/// Also the floor that keeps the "one of every class" retry from spinning: four classes cannot
/// all fit in fewer than four characters.
pub const MIN_LENGTH: usize = 8;

/// Longest password this generator will produce. Beyond this the limit is what sites accept,
/// not what is safe.
pub const MAX_LENGTH: usize = 128;

// Four classes cannot all appear in a shorter password, and the retry loop would spin forever
// looking for one that does. Enforced at compile time so lowering it fails the build.
const _: () = assert!(MIN_LENGTH >= 4);

/// How many times to redraw looking for a password containing every selected class.
///
/// At the minimum length with all four classes the chance of missing one is small, so this is
/// far more headroom than the loop ever uses. It exists so a mistake in the class predicates
/// fails loudly instead of hanging the application.
const MAX_ATTEMPTS: usize = 1000;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GeneratorError {
    #[error("choose at least one kind of character")]
    NoCharacterClasses,
    #[error("the length must be between {minimum} and {maximum}")]
    LengthOutOfRange { minimum: usize, maximum: usize },
    #[error("the system random number generator is unavailable")]
    RandomUnavailable,
    #[error("could not produce a password containing every selected kind of character")]
    Exhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratorOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedPassword {
    pub password: SecretString,
    /// How many bits of guessing this password is worth.
    ///
    /// Reported as a number rather than a "weak / strong" verdict. A meter that calls a
    /// twelve-character password strong is telling the user something the arithmetic does not
    /// support, and it hides what excluding ambiguous characters costs.
    pub entropy_bits: f64,
}

/// The characters a given set of options draws from.
pub fn alphabet(options: GeneratorOptions) -> Vec<char> {
    let mut classes = String::new();

    if options.lowercase {
        classes.push_str(LOWERCASE);
    }
    if options.uppercase {
        classes.push_str(UPPERCASE);
    }
    if options.digits {
        classes.push_str(DIGITS);
    }
    if options.symbols {
        classes.push_str(SYMBOLS);
    }

    classes
        .chars()
        .filter(|c| !options.avoid_ambiguous || !AMBIGUOUS.contains(*c))
        .collect()
}

fn satisfies_every_class(password: &str, options: GeneratorOptions) -> bool {
    let has = |wanted: bool, class: &str| {
        !wanted
            || password
                .chars()
                .any(|c| class.contains(c) && !(options.avoid_ambiguous && AMBIGUOUS.contains(c)))
    };

    has(options.lowercase, LOWERCASE)
        && has(options.uppercase, UPPERCASE)
        && has(options.digits, DIGITS)
        && has(options.symbols, SYMBOLS)
}

/// Draws a password from the system's random number generator.
pub fn generate(options: GeneratorOptions) -> Result<GeneratedPassword, GeneratorError> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&options.length) {
        return Err(GeneratorError::LengthOutOfRange {
            minimum: MIN_LENGTH,
            maximum: MAX_LENGTH,
        });
    }

    let alphabet = alphabet(options);
    if alphabet.is_empty() {
        return Err(GeneratorError::NoCharacterClasses);
    }

    // Asks the system source for a byte before any password depends on it, so an unavailable
    // generator is reported rather than discovered halfway through.
    let mut probe = [0u8; 1];
    SysRng
        .try_fill_bytes(&mut probe)
        .map_err(|_| GeneratorError::RandomUnavailable)?;

    // `choose` needs an infallible `Rng`. Wrapping is sound here only because the probe above
    // succeeded: on a desktop, the system source does not start working and then stop.
    let mut rng = UnwrapErr(SysRng);

    for _ in 0..MAX_ATTEMPTS {
        let password: String = (0..options.length)
            .map(|_| {
                // `choose` with the `unbiased` feature is rejection sampling, so every character
                // is equally likely. Modulo would tilt the distribution towards the start of the
                // alphabet — invisible in the output, and a straight loss of entropy.
                *alphabet
                    .choose(&mut rng)
                    .expect("the alphabet is not empty")
            })
            .collect();

        if satisfies_every_class(&password, options) {
            let entropy_bits = options.length as f64 * (alphabet.len() as f64).log2();

            return Ok(GeneratedPassword {
                password: SecretString::new(password),
                entropy_bits,
            });
        }
    }

    Err(GeneratorError::Exhausted)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;

    fn options() -> GeneratorOptions {
        GeneratorOptions {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }

    fn generated(options: GeneratorOptions) -> String {
        generate(options)
            .expect("generation must succeed")
            .password
            .expose()
            .to_owned()
    }

    #[test]
    fn produces_the_requested_length() {
        let password = generated(GeneratorOptions {
            length: 32,
            ..options()
        });

        assert_eq!(password.chars().count(), 32);
    }

    #[test]
    fn uses_only_the_selected_classes() {
        let password = generated(GeneratorOptions {
            uppercase: false,
            symbols: false,
            ..options()
        });

        assert!(password
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn includes_at_least_one_of_every_selected_class() {
        for _ in 0..20 {
            let password = generated(GeneratorOptions {
                length: 8,
                ..options()
            });

            // Plenty of sites reject a password that misses a class. Retrying until every class
            // appears keeps the result uniform over the passwords that satisfy the rule, which
            // forcing characters into fixed positions would not.
            assert!(
                password.chars().any(|c| c.is_ascii_lowercase()),
                "{password}"
            );
            assert!(
                password.chars().any(|c| c.is_ascii_uppercase()),
                "{password}"
            );
            assert!(password.chars().any(|c| c.is_ascii_digit()), "{password}");
            assert!(password.chars().any(|c| SYMBOLS.contains(c)), "{password}");
        }
    }

    #[test]
    fn leaves_out_ambiguous_characters_when_asked() {
        let password = generated(GeneratorOptions {
            length: 128,
            avoid_ambiguous: true,
            ..options()
        });

        assert!(
            password.chars().all(|c| !AMBIGUOUS.contains(c)),
            "{password}"
        );
    }

    #[test]
    fn includes_ambiguous_characters_otherwise() {
        // Excluding them costs entropy, so it must not happen behind the user's back.
        let alphabet = alphabet(GeneratorOptions {
            avoid_ambiguous: false,
            ..options()
        });

        assert!(AMBIGUOUS.chars().all(|c| alphabet.contains(&c)));
    }

    #[test]
    fn every_character_in_the_alphabet_is_reachable() {
        let options = GeneratorOptions {
            length: 64,
            ..options()
        };
        let expected: HashSet<char> = alphabet(options).into_iter().collect();

        let mut seen: HashSet<char> = HashSet::new();
        for _ in 0..200 {
            seen.extend(generated(options).chars());
        }

        // A weak check for a specific failure: an off-by-one in the sampling range silently
        // makes the last character of the alphabet impossible, and nothing else would notice.
        assert_eq!(seen, expected);
    }

    #[test]
    fn does_not_repeat_itself() {
        assert_ne!(generated(options()), generated(options()));
    }

    #[test]
    fn reports_the_entropy_it_actually_produced() {
        let options = GeneratorOptions {
            length: 20,
            uppercase: false,
            symbols: false,
            avoid_ambiguous: false,
            ..options()
        };

        let result = generate(options).unwrap();

        // 26 letters plus 10 digits, twenty times over.
        let expected = 20.0 * 36f64.log2();
        assert!((result.entropy_bits - expected).abs() < 0.001);
    }

    #[test]
    fn reports_less_entropy_when_ambiguous_characters_are_excluded() {
        let with = generate(GeneratorOptions {
            avoid_ambiguous: false,
            ..options()
        })
        .unwrap();
        let without = generate(GeneratorOptions {
            avoid_ambiguous: true,
            ..options()
        })
        .unwrap();

        // The number is the honest way to show strength. A meter that says "strong" either way
        // hides the cost of the convenience.
        assert!(without.entropy_bits < with.entropy_bits);
    }

    #[test]
    fn refuses_to_generate_from_nothing() {
        let result = generate(GeneratorOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..options()
        });

        assert_eq!(result.unwrap_err(), GeneratorError::NoCharacterClasses);
    }

    #[test]
    fn refuses_a_length_outside_the_supported_range() {
        assert_eq!(
            generate(GeneratorOptions {
                length: MIN_LENGTH - 1,
                ..options()
            })
            .unwrap_err(),
            GeneratorError::LengthOutOfRange {
                minimum: MIN_LENGTH,
                maximum: MAX_LENGTH
            }
        );
        assert_eq!(
            generate(GeneratorOptions {
                length: MAX_LENGTH + 1,
                ..options()
            })
            .unwrap_err(),
            GeneratorError::LengthOutOfRange {
                minimum: MIN_LENGTH,
                maximum: MAX_LENGTH
            }
        );
    }

    #[test]
    fn the_generated_password_does_not_render_itself() {
        let result = generate(options()).unwrap();

        assert_eq!(format!("{:?}", result.password), "SecretString(<redacted>)");
    }

    #[test]
    fn error_messages_do_not_mention_secrets() {
        for error in [
            GeneratorError::NoCharacterClasses,
            GeneratorError::LengthOutOfRange {
                minimum: MIN_LENGTH,
                maximum: MAX_LENGTH,
            },
            GeneratorError::RandomUnavailable,
        ] {
            let message = error.to_string().to_lowercase();

            assert!(!message.is_empty());
            assert!(!message.contains("password must be"));
        }
    }
}
