//! Turning a master password into the 256-bit key that encrypts the vault.
//!
//! The vault file is assumed to be readable by an attacker. What stands between that file and
//! the credentials inside it is the cost of this derivation, so every parameter here is a
//! security decision rather than a performance one.

use std::fmt;

use argon2::{Algorithm, Argon2, Block, Params, Version};
use rand::rngs::SysRng;
use rand::TryRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of a derived key, in bytes. AES-256-GCM takes a 32-byte key.
pub const KEY_LEN: usize = 32;

/// Length of a vault salt, in bytes. Matches Argon2's recommended salt length.
pub const SALT_LEN: usize = 16;

// Argon2 accepts salts from 8 bytes, but 16 is what it recommends and what this format commits
// to. Enforced at compile time so shrinking it fails the build rather than a test.
const _: () = assert!(SALT_LEN >= argon2::RECOMMENDED_SALT_LEN);

/// Errors are deliberately coarse: an attacker who can read them must learn nothing about the
/// password, the key, or how close a guess was.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KdfError {
    #[error("invalid key derivation parameters")]
    InvalidParams,
    #[error("key derivation failed")]
    DerivationFailed,
    #[error("the system random number generator is unavailable")]
    RandomUnavailable,
}

/// A per-vault salt. Not secret — it is stored in the vault header in the clear — but it must be
/// unique, or two vaults sharing a master password would share a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Salt([u8; SALT_LEN]);

impl Salt {
    /// Draws a fresh salt from the operating system's CSPRNG.
    pub fn generate() -> Result<Self, KdfError> {
        let mut bytes = [0u8; SALT_LEN];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| KdfError::RandomUnavailable)?;

        Ok(Self(bytes))
    }

    /// Rebuilds a salt read back from a vault header.
    pub const fn from_bytes(bytes: [u8; SALT_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; SALT_LEN] {
        &self.0
    }
}

/// Argon2id cost parameters.
///
/// These are stored per vault rather than hardcoded at the call site: a vault written today must
/// still open after the recommended cost is raised, so the parameters it was sealed with have to
/// travel with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
}

impl KdfParams {
    /// Cost used when sealing a new vault.
    ///
    /// 128 MiB / 3 passes measured at ~220 ms on an Apple M-series machine — see the `kdf_timing`
    /// example, which is the tool for retuning this. That is well above the OWASP floor of
    /// 19 MiB / 2 passes, and twice the memory hardness of Bitwarden's default.
    ///
    /// Expect several times that on a low-end machine. Re-measure before raising it.
    ///
    /// Memory is the lever worth pulling, not iterations: it is what denies an attacker cheap
    /// GPU and ASIC parallelism. Iterations only buy linear time, which they can also buy.
    ///
    /// `lanes` stays at 1 on purpose. The `argon2` crate computes lanes sequentially unless its
    /// `parallel` feature is enabled, so raising it would slow honest unlocks without denying an
    /// attacker anything: they can always run their own lanes in parallel.
    pub const RECOMMENDED: Self = Self {
        memory_kib: 128 * 1024,
        iterations: 3,
        lanes: 1,
    };

    /// Validates a parameter set, rejecting anything Argon2 itself would refuse.
    pub fn new(memory_kib: u32, iterations: u32, lanes: u32) -> Result<Self, KdfError> {
        // Validation is delegated to argon2 so our bounds can never drift from the ones it
        // actually enforces.
        argon2_params(memory_kib, iterations, lanes)?;

        Ok(Self {
            memory_kib,
            iterations,
            lanes,
        })
    }

    pub const fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    pub const fn iterations(&self) -> u32 {
        self.iterations
    }

    pub const fn lanes(&self) -> u32 {
        self.lanes
    }
}

fn argon2_params(memory_kib: u32, iterations: u32, lanes: u32) -> Result<Params, KdfError> {
    Params::new(memory_kib, iterations, lanes, Some(KEY_LEN)).map_err(|_| KdfError::InvalidParams)
}

/// A key derived from the master password. Zeroized when dropped.
///
/// There is no `Clone`, `Display`, `Serialize`, or derived `Debug` on purpose: every one of them
/// is a way for key material to end up somewhere it cannot be wiped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; KEY_LEN]);

impl MasterKey {
    /// Reveals the raw key bytes.
    ///
    /// Named to stand out in review. The only legitimate call site is the moment the key is
    /// handed to the cipher.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

/// Derives the vault key from a master password.
///
/// Deriving the same key requires the same password, salt and parameters — which is why all
/// three, except the password, live in the vault header.
pub fn derive_key(password: &[u8], salt: &Salt, params: KdfParams) -> Result<MasterKey, KdfError> {
    let cost = argon2_params(params.memory_kib, params.iterations, params.lanes)?;
    let block_count = cost.block_count();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, cost);

    // The scratch space is owned here rather than left to `hash_password_into`, which allocates
    // the same buffer and drops it without wiping. The last block it leaves behind is one
    // BLAKE2b away from the key, and this buffer is large enough to reach swap or a core dump.
    let mut blocks = vec![Block::default(); block_count];
    let mut key = [0u8; KEY_LEN];

    let outcome =
        argon2.hash_password_into_with_memory(password, salt.as_bytes(), &mut key, &mut blocks);
    blocks.zeroize();
    outcome.map_err(|_| KdfError::DerivationFailed)?;

    let derived = MasterKey(key);
    key.zeroize();

    Ok(derived)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deliberately weak parameters. These tests assert derivation *behaviour*; running them at
    /// the real cost would make the suite unusable. `KdfParams::RECOMMENDED` is guarded
    /// separately by `recommended_parameters_meet_the_owasp_floor`.
    fn cheap_params() -> KdfParams {
        KdfParams::new(8, 1, 1).expect("cheap test parameters must be valid")
    }

    fn salt_of(byte: u8) -> Salt {
        Salt::from_bytes([byte; SALT_LEN])
    }

    #[test]
    fn derives_the_same_key_for_the_same_password_and_salt() {
        let salt = salt_of(0xA1);

        let first = derive_key(b"correct horse battery staple", &salt, cheap_params()).unwrap();
        let second = derive_key(b"correct horse battery staple", &salt, cheap_params()).unwrap();

        assert_eq!(first.expose(), second.expose());
    }

    #[test]
    fn derives_a_different_key_when_the_salt_changes() {
        let password = b"correct horse battery staple";

        let first = derive_key(password, &salt_of(0x01), cheap_params()).unwrap();
        let second = derive_key(password, &salt_of(0x02), cheap_params()).unwrap();

        assert_ne!(first.expose(), second.expose());
    }

    #[test]
    fn derives_a_different_key_when_the_password_changes() {
        let salt = salt_of(0xA1);

        let first = derive_key(b"correct horse battery staple", &salt, cheap_params()).unwrap();
        let second = derive_key(b"correct horse battery stapl3", &salt, cheap_params()).unwrap();

        assert_ne!(first.expose(), second.expose());
    }

    #[test]
    fn derives_a_different_key_when_the_parameters_change() {
        let salt = salt_of(0xA1);
        let password = b"correct horse battery staple";

        let cheap = derive_key(password, &salt, cheap_params()).unwrap();
        let costlier = derive_key(password, &salt, KdfParams::new(16, 2, 1).unwrap()).unwrap();

        assert_ne!(cheap.expose(), costlier.expose());
    }

    #[test]
    fn derives_a_256_bit_key() {
        let key = derive_key(b"hunter2", &salt_of(0xA1), cheap_params()).unwrap();

        assert_eq!(key.expose().len(), 32);
    }

    #[test]
    fn accepts_an_empty_password() {
        // Rejecting weak master passwords is a policy decision that belongs to the vault layer.
        // The KDF is a primitive and must stay predictable.
        let key = derive_key(b"", &salt_of(0xA1), cheap_params());

        assert!(key.is_ok());
    }

    #[test]
    fn generated_salts_differ() {
        let first = Salt::generate().unwrap();
        let second = Salt::generate().unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn generated_salts_are_not_all_zero() {
        let salt = Salt::generate().unwrap();

        assert_ne!(salt.as_bytes(), &[0u8; SALT_LEN]);
    }

    #[test]
    fn salt_round_trips_through_bytes() {
        let bytes = [0x7Fu8; SALT_LEN];

        assert_eq!(Salt::from_bytes(bytes).as_bytes(), &bytes);
    }

    #[test]
    fn rejects_parameters_below_the_argon2_minimum() {
        assert!(matches!(
            KdfParams::new(7, 1, 1),
            Err(KdfError::InvalidParams)
        ));
        assert!(matches!(
            KdfParams::new(8, 0, 1),
            Err(KdfError::InvalidParams)
        ));
        assert!(matches!(
            KdfParams::new(8, 1, 0),
            Err(KdfError::InvalidParams)
        ));
    }

    #[test]
    fn recommended_parameters_meet_the_owasp_floor() {
        // OWASP Password Storage Cheat Sheet, Argon2id: m=19 MiB, t=2, p=1.
        // Weakening these below the floor is the single easiest way to break this application.
        let recommended = KdfParams::RECOMMENDED;

        assert!(recommended.memory_kib() >= 19 * 1024);
        assert!(recommended.iterations() >= 2);
        assert!(recommended.lanes() >= 1);
        assert!(KdfParams::new(
            recommended.memory_kib(),
            recommended.iterations(),
            recommended.lanes()
        )
        .is_ok());
    }

    #[test]
    fn master_key_debug_output_carries_no_key_material() {
        let first = derive_key(b"one", &salt_of(0x01), cheap_params()).unwrap();
        let second = derive_key(b"two", &salt_of(0x02), cheap_params()).unwrap();
        assert_ne!(first.expose(), second.expose());

        // Two different keys rendering identically is only possible if Debug carries none of
        // the key. Substring checks would be weaker and would false-positive on hex pairs that
        // happen to appear in the redaction text.
        assert_eq!(format!("{:?}", first), format!("{:?}", second));
    }

    /// Locks the derivation against accidental change.
    ///
    /// This is not an independent RFC 9106 vector — it was produced by this implementation. Its
    /// job is to fail loudly if a refactor, a dependency bump, or a parameter tweak alters the
    /// key for a given input. That change would not break anything visibly: it would silently
    /// make every vault written before it impossible to open.
    #[test]
    fn derivation_matches_the_locked_known_answer() {
        const EXPECTED: &str = "f6893d3e53f934c7cce81cf0a3624baec24367ec85565ba8a890a1de6a7a4fdc";

        let key = derive_key(
            b"correct horse battery staple",
            &Salt::from_bytes([0x42; SALT_LEN]),
            KdfParams::new(32, 2, 1).unwrap(),
        )
        .unwrap();

        let actual: String = key
            .expose()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        assert_eq!(actual, EXPECTED);
    }

    #[test]
    fn error_messages_do_not_mention_secrets() {
        for error in [
            KdfError::InvalidParams,
            KdfError::DerivationFailed,
            KdfError::RandomUnavailable,
        ] {
            let message = error.to_string();

            assert!(!message.is_empty());
            assert!(!message.to_lowercase().contains("password"));
            assert!(!message.to_lowercase().contains("key material"));
        }
    }
}
