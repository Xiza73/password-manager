//! The on-disk vault format.
//!
//! ```text
//! offset  size  field
//!      0     8  magic "PWMVAULT"          ┐
//!      8     2  format version (u16 LE)   │
//!     10     4  Argon2id memory in KiB    ├─ authenticated as associated data
//!     14     4  Argon2id iterations       │
//!     18     4  Argon2id lanes            │
//!     22    16  salt                      ┘
//!     38    12  nonce
//!     50     …  ciphertext ‖ tag
//! ```
//!
//! Everything before the nonce is passed to the cipher as associated data. That is what makes
//! the header tamper-evident even though it is stored in the clear: an attacker who rewrites the
//! stored Argon2 cost down to the minimum, hoping to brute-force the master password cheaply,
//! breaks authentication of the body instead.
//!
//! The nonce is deliberately outside that region. GCM already takes it as an input to the tag,
//! so modifying it fails authentication anyway — and including it would be circular, since the
//! nonce is generated during sealing.

use zeroize::Zeroizing;

use crate::crypto::cipher::{open, seal, CipherError, Nonce, SealedBox, NONCE_LEN, TAG_LEN};
use crate::crypto::kdf::{derive_key, KdfError, KdfParams, MasterKey, Salt, SALT_LEN};

/// Identifies the file type. Present so a wrong path fails immediately instead of looking like a
/// corrupt vault, or worse, like a wrong password.
pub const MAGIC: &[u8; 8] = b"PWMVAULT";

/// Bumped whenever the layout or the cryptographic construction changes.
pub const FORMAT_VERSION: u16 = 1;

pub const VERSION_OFFSET: usize = MAGIC.len();
pub const MEMORY_OFFSET: usize = VERSION_OFFSET + 2;
pub const ITERATIONS_OFFSET: usize = MEMORY_OFFSET + 4;
pub const LANES_OFFSET: usize = ITERATIONS_OFFSET + 4;
pub const SALT_OFFSET: usize = LANES_OFFSET + 4;

/// Length of the region authenticated as associated data.
pub const HEADER_LEN: usize = SALT_OFFSET + SALT_LEN;

/// Smallest possible well-formed file: header, nonce, and a tag over an empty body.
pub const MIN_FILE_LEN: usize = HEADER_LEN + NONCE_LEN + TAG_LEN;

/// Upper bounds on the Argon2 cost this build will honour.
///
/// All three come out of the file, and anyone who can write the file can set them. Argon2's own
/// limits are `u32::MAX` for memory and time, so without ceilings here a hostile vault turns one
/// unlock attempt into an unbounded allocation or a derivation that never finishes — and since
/// the session lock is held for the whole derivation, the application wedges until it is killed.
/// The file is on disk, so it happens again on the next launch.
///
/// Each is far above anything worth configuring and far below anything that hurts.
pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;
pub const MAX_ITERATIONS: u32 = 16;
pub const MAX_LANES: u32 = 8;

// A ceiling that excluded what this build itself writes would make every new vault unopenable,
// which is a worse failure than the one it prevents.
const _: () = assert!(KdfParams::RECOMMENDED.memory_kib() <= MAX_MEMORY_KIB);
const _: () = assert!(KdfParams::RECOMMENDED.iterations() <= MAX_ITERATIONS);
const _: () = assert!(KdfParams::RECOMMENDED.lanes() <= MAX_LANES);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VaultError {
    #[error("this file is not a vault")]
    NotAVault,
    #[error("this vault was written by a newer version of the application (format {0})")]
    UnsupportedVersion(u16),
    #[error("this vault is malformed")]
    Malformed,
    #[error("the vault could not be unlocked")]
    Unauthentic,
    #[error("the system random number generator is unavailable")]
    RandomUnavailable,
    #[error("the vault could not be sealed")]
    EncryptionFailed,
}

impl From<KdfError> for VaultError {
    fn from(error: KdfError) -> Self {
        match error {
            KdfError::RandomUnavailable => Self::RandomUnavailable,
            // Parameters that argon2 refuses can only reach us from a corrupt or hostile file.
            KdfError::InvalidParams => Self::Malformed,
            KdfError::DerivationFailed => Self::EncryptionFailed,
        }
    }
}

impl From<CipherError> for VaultError {
    fn from(error: CipherError) -> Self {
        match error {
            CipherError::RandomUnavailable => Self::RandomUnavailable,
            CipherError::EncryptionFailed => Self::EncryptionFailed,
            // Wrong password and deliberate tampering are the same answer on purpose. See
            // `CipherError::Unauthentic`.
            CipherError::Unauthentic => Self::Unauthentic,
        }
    }
}

fn header_bytes(params: KdfParams, salt: &Salt) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];

    header[..MAGIC.len()].copy_from_slice(MAGIC);
    header[VERSION_OFFSET..MEMORY_OFFSET].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    header[MEMORY_OFFSET..ITERATIONS_OFFSET].copy_from_slice(&params.memory_kib().to_le_bytes());
    header[ITERATIONS_OFFSET..LANES_OFFSET].copy_from_slice(&params.iterations().to_le_bytes());
    header[LANES_OFFSET..SALT_OFFSET].copy_from_slice(&params.lanes().to_le_bytes());
    header[SALT_OFFSET..].copy_from_slice(salt.as_bytes());

    header
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut field = [0u8; 4];
    field.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(field)
}

/// Seals `body` into the bytes of a vault file.
///
/// A fresh salt is drawn on every call, so re-saving an unchanged vault produces an entirely
/// different file. That is deliberate: equal files would tell an observer that nothing changed.
pub fn encode(password: &[u8], body: &[u8], params: KdfParams) -> Result<Vec<u8>, VaultError> {
    encode_with(&SealingKey::create(password, params)?, body)
}

/// The parts of a vault file that can be read without the master password.
struct Parsed<'a> {
    header: &'a [u8],
    params: KdfParams,
    salt: Salt,
    nonce: Nonce,
    ciphertext: &'a [u8],
}

fn parse(file: &[u8]) -> Result<Parsed<'_>, VaultError> {
    // Identity is decided before length, and on the prefix that is actually present. Picking the
    // wrong file and holding a truncated vault are different problems with different answers —
    // "choose another file" versus "restore from a backup" — so they must not collapse into one
    // error. An empty file reads as a vault destroyed mid-write, not as someone else's document.
    if file.is_empty() {
        return Err(VaultError::Malformed);
    }

    let comparable = MAGIC.len().min(file.len());
    if file[..comparable] != MAGIC[..comparable] {
        return Err(VaultError::NotAVault);
    }

    if file.len() < MIN_FILE_LEN {
        return Err(VaultError::Malformed);
    }

    let header = &file[..HEADER_LEN];

    let version = u16::from_le_bytes([header[VERSION_OFFSET], header[VERSION_OFFSET + 1]]);
    if version != FORMAT_VERSION {
        return Err(VaultError::UnsupportedVersion(version));
    }

    // All three ceilings are checked before anything is allocated or derived, so a hostile cost
    // is refused rather than honoured.
    let memory_kib = read_u32(header, MEMORY_OFFSET);
    let iterations = read_u32(header, ITERATIONS_OFFSET);
    let lanes = read_u32(header, LANES_OFFSET);

    if memory_kib > MAX_MEMORY_KIB || iterations > MAX_ITERATIONS || lanes > MAX_LANES {
        return Err(VaultError::Malformed);
    }

    let params = KdfParams::new(memory_kib, iterations, lanes)?;

    let mut salt_bytes = [0u8; SALT_LEN];
    salt_bytes.copy_from_slice(&header[SALT_OFFSET..HEADER_LEN]);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&file[HEADER_LEN..HEADER_LEN + NONCE_LEN]);

    Ok(Parsed {
        header,
        params,
        salt: Salt::from_bytes(salt_bytes),
        nonce: Nonce::from_bytes(nonce_bytes),
        ciphertext: &file[HEADER_LEN + NONCE_LEN..],
    })
}

/// A derived key together with the salt and cost it belongs to.
///
/// This exists so an unlocked session can reseal the vault on every edit without asking for the
/// master password again — and, more to the point, without keeping the master password in memory
/// for as long as the vault is open. Holding the derived key is strictly less to lose.
///
/// The salt stays fixed for the life of the key. Re-salting on every save would buy nothing: the
/// salt's job is to stop precomputation across vaults, and a fresh nonce per save is what keeps
/// two writes from looking alike.
pub struct SealingKey {
    key: MasterKey,
    salt: Salt,
    params: KdfParams,
}

impl SealingKey {
    /// Derives a key for a brand new vault, with a freshly drawn salt.
    pub fn create(password: &[u8], params: KdfParams) -> Result<Self, VaultError> {
        let salt = Salt::generate()?;

        Ok(Self {
            key: derive_key(password, &salt, params)?,
            salt,
            params,
        })
    }

    /// Derives the key an existing vault was sealed with, using the salt and cost it carries.
    ///
    /// Whether the password was right is not decided here — nothing has been authenticated yet.
    /// Only unsealing the body can answer that.
    pub fn from_file(password: &[u8], file: &[u8]) -> Result<Self, VaultError> {
        let parsed = parse(file)?;

        Ok(Self {
            key: derive_key(password, &parsed.salt, parsed.params)?,
            salt: parsed.salt,
            params: parsed.params,
        })
    }

    pub fn params(&self) -> KdfParams {
        self.params
    }
}

/// Seals `body` with an existing key.
pub fn encode_with(sealing: &SealingKey, body: &[u8]) -> Result<Vec<u8>, VaultError> {
    let header = header_bytes(sealing.params, &sealing.salt);
    let sealed = seal(&sealing.key, body, &header)?;

    let mut file = Vec::with_capacity(MIN_FILE_LEN + body.len());
    file.extend_from_slice(&header);
    file.extend_from_slice(sealed.nonce().as_bytes());
    file.extend_from_slice(sealed.ciphertext());

    Ok(file)
}

/// Unseals a vault file with an already derived key.
pub fn decode_with(sealing: &SealingKey, file: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let parsed = parse(file)?;

    // A key derived for one salt and cost cannot open a file carrying different ones. That would
    // fail authentication regardless; refusing here says why instead of blaming the password.
    if parsed.salt != sealing.salt || parsed.params != sealing.params {
        return Err(VaultError::Unauthentic);
    }

    let sealed = SealedBox::from_parts(parsed.nonce, parsed.ciphertext.to_vec());

    Ok(open(&sealing.key, &sealed, parsed.header)?)
}

/// Verifies and unseals the bytes of a vault file.
///
/// The Argon2 parameters come from the file rather than from the current recommendation, so a
/// vault written before the cost was raised still opens.
pub fn decode(password: &[u8], file: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    decode_with(&SealingKey::from_file(password, file)?, file)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &[u8] = b"correct horse battery staple";
    const BODY: &[u8] = b"[{\"site\":\"github.com\",\"password\":\"hunter2\"}]";

    fn cheap() -> KdfParams {
        KdfParams::new(8, 1, 1).expect("cheap test parameters must be valid")
    }

    fn encoded() -> Vec<u8> {
        encode(PASSWORD, BODY, cheap()).expect("encoding must succeed")
    }

    fn flip_bit(bytes: &mut [u8], index: usize) {
        bytes[index] ^= 0b0000_0001;
    }

    #[test]
    fn round_trips_a_body() {
        let opened = decode(PASSWORD, &encoded()).unwrap();

        assert_eq!(opened.as_slice(), BODY);
    }

    #[test]
    fn round_trips_an_empty_body() {
        let file = encode(PASSWORD, b"", cheap()).unwrap();

        assert!(decode(PASSWORD, &file).unwrap().is_empty());
    }

    #[test]
    fn rejects_a_wrong_password() {
        let result = decode(b"not the password", &encoded());

        assert_eq!(result.unwrap_err(), VaultError::Unauthentic);
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let mut file = encoded();
        let last = file.len() - 1;
        flip_bit(&mut file, last);

        assert_eq!(
            decode(PASSWORD, &file).unwrap_err(),
            VaultError::Unauthentic
        );
    }

    #[test]
    fn rejects_a_tampered_nonce() {
        let mut file = encoded();
        flip_bit(&mut file, HEADER_LEN);

        assert_eq!(
            decode(PASSWORD, &file).unwrap_err(),
            VaultError::Unauthentic
        );
    }

    #[test]
    fn rejects_a_tampered_salt() {
        let mut file = encoded();
        flip_bit(&mut file, SALT_OFFSET);

        // Caught because the salt feeds key derivation, so editing it yields a different key —
        // not because of the associated data. See `associated_data_is_defence_in_depth_today`.
        assert_eq!(
            decode(PASSWORD, &file).unwrap_err(),
            VaultError::Unauthentic
        );
    }

    #[test]
    fn rejects_downgraded_kdf_parameters() {
        let file = encode(PASSWORD, BODY, KdfParams::new(16, 2, 1).unwrap()).unwrap();

        let mut downgraded = file.clone();
        downgraded[MEMORY_OFFSET..MEMORY_OFFSET + 4].copy_from_slice(&8u32.to_le_bytes());

        // The attack: rewrite the stored cost down to the minimum, then brute-force the master
        // password cheaply. It fails because the cost is a key-derivation input, so a rewritten
        // cost derives a different key. The associated data covers the same ground a second
        // time; this assertion does not distinguish the two.
        assert_eq!(
            decode(PASSWORD, &downgraded).unwrap_err(),
            VaultError::Unauthentic
        );
    }

    /// Records what the associated data does and does not buy right now.
    ///
    /// Every field in the header is either an input to key derivation (salt, cost) or is checked
    /// explicitly before the cipher runs (magic, version). Tampering with any of them is caught
    /// without the binding, which is why no test in this module fails if it is removed — a fact
    /// worth stating, because the tests above read as though they prove otherwise.
    ///
    /// The binding stays because it stops being redundant the moment the header grows a field
    /// that is neither: a body compression flag, a cipher selector, a record count. Whoever adds
    /// that field gets the protection without having to know it was needed.
    #[test]
    fn associated_data_is_defence_in_depth_today() {
        let mut file = encoded();

        for offset in [0, VERSION_OFFSET, MEMORY_OFFSET, SALT_OFFSET] {
            let original = file[offset];
            flip_bit(&mut file, offset);

            assert!(
                decode(PASSWORD, &file).is_err(),
                "a modified header byte at offset {offset} must never open"
            );

            file[offset] = original;
        }
    }

    #[test]
    fn opens_a_vault_sealed_with_different_parameters() {
        // Raising the recommended cost must never strand vaults written before the change.
        let file = encode(PASSWORD, BODY, KdfParams::new(16, 2, 1).unwrap()).unwrap();

        assert_eq!(decode(PASSWORD, &file).unwrap().as_slice(), BODY);
    }

    #[test]
    fn rejects_a_file_that_is_not_a_vault() {
        let result = decode(PASSWORD, &[0xFF; MIN_FILE_LEN]);

        assert_eq!(result.unwrap_err(), VaultError::NotAVault);
    }

    #[test]
    fn rejects_an_unsupported_version() {
        let mut file = encoded();
        file[VERSION_OFFSET..VERSION_OFFSET + 2].copy_from_slice(&99u16.to_le_bytes());

        // A newer vault must be refused with a clear answer, never opened on a guess and never
        // written back in an older shape.
        assert_eq!(
            decode(PASSWORD, &file).unwrap_err(),
            VaultError::UnsupportedVersion(99)
        );
    }

    #[test]
    fn rejects_a_truncated_file() {
        let mut file = encoded();
        file.truncate(MIN_FILE_LEN - 1);

        assert_eq!(decode(PASSWORD, &file).unwrap_err(), VaultError::Malformed);
    }

    #[test]
    fn rejects_an_empty_file() {
        assert_eq!(decode(PASSWORD, &[]).unwrap_err(), VaultError::Malformed);
    }

    #[test]
    fn tells_a_foreign_file_apart_from_a_truncated_vault() {
        // Both are too short to be a vault, and the two answers are not interchangeable.
        assert_eq!(
            decode(PASSWORD, b"a shopping list").unwrap_err(),
            VaultError::NotAVault
        );
        assert_eq!(
            decode(PASSWORD, &MAGIC[..4]).unwrap_err(),
            VaultError::Malformed
        );
    }

    #[test]
    fn rejects_impossible_kdf_parameters() {
        let mut file = encoded();
        file[LANES_OFFSET..LANES_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());

        assert_eq!(decode(PASSWORD, &file).unwrap_err(), VaultError::Malformed);
    }

    #[test]
    fn rejects_a_memory_cost_beyond_the_ceiling() {
        let mut file = encoded();
        let absurd = MAX_MEMORY_KIB + 1;
        file[MEMORY_OFFSET..MEMORY_OFFSET + 4].copy_from_slice(&absurd.to_le_bytes());

        // Without a ceiling, anyone who can write the vault file can make an unlock attempt
        // allocate arbitrary memory. The cap is refused before any allocation happens.
        assert_eq!(decode(PASSWORD, &file).unwrap_err(), VaultError::Malformed);
    }

    #[test]
    fn rejects_a_time_cost_beyond_the_ceiling() {
        let mut file = encoded();
        file[ITERATIONS_OFFSET..ITERATIONS_OFFSET + 4]
            .copy_from_slice(&(MAX_ITERATIONS + 1).to_le_bytes());

        // Argon2's own upper bound on iterations is u32::MAX, so without a ceiling here a
        // hostile header makes an unlock attempt run effectively forever — holding the session
        // lock the whole time, which wedges the application until it is force-quit. Rejecting a
        // huge memory cost while accepting a huge time cost applies the defence by halves.
        assert_eq!(decode(PASSWORD, &file).unwrap_err(), VaultError::Malformed);
    }

    #[test]
    fn rejects_a_parallelism_beyond_the_ceiling() {
        let mut file = encoded();
        file[LANES_OFFSET..LANES_OFFSET + 4].copy_from_slice(&(MAX_LANES + 1).to_le_bytes());

        assert_eq!(decode(PASSWORD, &file).unwrap_err(), VaultError::Malformed);
    }

    #[test]
    fn the_ceilings_leave_room_for_the_recommended_parameters() {
        // A ceiling that excluded what this build itself writes would make every new vault
        // unopenable, which is a worse failure than the one it prevents.
        let recommended = KdfParams::RECOMMENDED;

        assert!(recommended.memory_kib() <= MAX_MEMORY_KIB);
        assert!(recommended.iterations() <= MAX_ITERATIONS);
        assert!(recommended.lanes() <= MAX_LANES);
    }

    #[test]
    fn encodes_the_same_body_differently_every_time() {
        // A fresh salt and nonce per write; two saves of an unchanged vault must not look equal.
        assert_ne!(encoded(), encoded());
    }

    #[test]
    fn does_not_contain_the_body_in_the_clear() {
        let file = encoded();

        assert!(!file.windows(BODY.len()).any(|window| window == BODY));
    }

    #[test]
    fn writes_the_documented_layout() {
        let file = encoded();

        assert_eq!(&file[..MAGIC.len()], MAGIC);
        assert_eq!(
            u16::from_le_bytes(file[VERSION_OFFSET..VERSION_OFFSET + 2].try_into().unwrap()),
            FORMAT_VERSION
        );
        assert_eq!(
            u32::from_le_bytes(file[MEMORY_OFFSET..MEMORY_OFFSET + 4].try_into().unwrap()),
            cheap().memory_kib()
        );
        assert_eq!(file.len(), MIN_FILE_LEN + BODY.len());
    }

    #[test]
    fn a_sealing_key_reopens_what_it_sealed() {
        let sealing = SealingKey::create(PASSWORD, cheap()).unwrap();

        let file = encode_with(&sealing, BODY).unwrap();

        assert_eq!(decode_with(&sealing, &file).unwrap().as_slice(), BODY);
        // And the password still opens it, because the key is only a cached derivation.
        assert_eq!(decode(PASSWORD, &file).unwrap().as_slice(), BODY);
    }

    #[test]
    fn resealing_keeps_the_salt_and_changes_the_nonce() {
        let sealing = SealingKey::create(PASSWORD, cheap()).unwrap();

        let first = encode_with(&sealing, BODY).unwrap();
        let second = encode_with(&sealing, BODY).unwrap();

        assert_eq!(first[..HEADER_LEN], second[..HEADER_LEN]);
        assert_ne!(
            first[HEADER_LEN..HEADER_LEN + 12],
            second[HEADER_LEN..HEADER_LEN + 12]
        );
    }

    #[test]
    fn a_key_from_one_vault_does_not_open_another() {
        // Two vaults, same password, different salts.
        let file = encode(PASSWORD, BODY, cheap()).unwrap();
        let other = SealingKey::create(PASSWORD, cheap()).unwrap();

        assert_eq!(
            decode_with(&other, &file).unwrap_err(),
            VaultError::Unauthentic
        );
    }

    #[test]
    fn a_key_derived_from_a_file_opens_that_file() {
        let file = encoded();

        let sealing = SealingKey::from_file(PASSWORD, &file).unwrap();

        assert_eq!(sealing.params(), cheap());
        assert_eq!(decode_with(&sealing, &file).unwrap().as_slice(), BODY);
    }

    #[test]
    fn a_key_derived_from_the_wrong_password_fails_only_on_use() {
        let file = encoded();

        // Deriving cannot fail: nothing has been authenticated yet, and pretending otherwise
        // would leak that the password was wrong before any tag was ever checked.
        let sealing = SealingKey::from_file(b"wrong", &file).unwrap();

        assert_eq!(
            decode_with(&sealing, &file).unwrap_err(),
            VaultError::Unauthentic
        );
    }

    #[test]
    fn error_messages_do_not_mention_secrets() {
        for error in [
            VaultError::NotAVault,
            VaultError::UnsupportedVersion(2),
            VaultError::Malformed,
            VaultError::Unauthentic,
            VaultError::RandomUnavailable,
            VaultError::EncryptionFailed,
        ] {
            let message = error.to_string().to_lowercase();

            assert!(!message.is_empty());
            assert!(!message.contains("password"));
            assert!(!message.contains("plaintext"));
        }
    }
}
