//! The on-disk vault format.
//!
//! ```text
//! offset  size  field
//!      0     8  magic "PWMVAULT"          ┐
//!      8     2  format version (u16 LE)   │
//!     10     8  save counter (u64 LE)     │
//!     18     4  Argon2id memory in KiB    ├─ authenticated as associated data
//!     22     4  Argon2id iterations       │
//!     26     4  Argon2id lanes            │
//!     30    16  salt                      ┘
//!     46    12  nonce
//!     58     …  ciphertext ‖ tag
//! ```
//!
//! Everything before the nonce is passed to the cipher as associated data. That is what makes
//! the header tamper-evident even though it is stored in the clear.
//!
//! The save counter is why that binding earns its place. Every other header field is either an
//! input to key derivation — rewrite it and the derived key changes — or a constant compared
//! before the cipher runs, so tampering with any of them was already caught without the
//! associated data. The counter is neither. Nothing else in this file checks it, and an attacker
//! presenting an older vault would simply raise it to whatever the last-seen value was. The
//! associated data is the only thing standing in the way.
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
///
/// Version 2 added the save counter. There is no reader for version 1: the format was never
/// released, so there are no version 1 vaults to migrate. A shipped product would need one.
pub const FORMAT_VERSION: u16 = 2;

pub const VERSION_OFFSET: usize = MAGIC.len();
pub const COUNTER_OFFSET: usize = VERSION_OFFSET + 2;
pub const MEMORY_OFFSET: usize = COUNTER_OFFSET + 8;
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

fn header_bytes(params: KdfParams, salt: &Salt, counter: u64) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];

    header[..MAGIC.len()].copy_from_slice(MAGIC);
    header[VERSION_OFFSET..COUNTER_OFFSET].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    header[COUNTER_OFFSET..MEMORY_OFFSET].copy_from_slice(&counter.to_le_bytes());
    header[MEMORY_OFFSET..ITERATIONS_OFFSET].copy_from_slice(&params.memory_kib().to_le_bytes());
    header[ITERATIONS_OFFSET..LANES_OFFSET].copy_from_slice(&params.iterations().to_le_bytes());
    header[LANES_OFFSET..SALT_OFFSET].copy_from_slice(&params.lanes().to_le_bytes());
    header[SALT_OFFSET..].copy_from_slice(salt.as_bytes());

    header
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut field = [0u8; 8];
    field.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(field)
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
    encode_with(&SealingKey::create(password, params)?, FIRST_SAVE, body)
}

/// The counter a brand new vault is sealed with. Starts at one so that zero can never be a
/// legitimate value, which makes an all-zero header obviously wrong rather than plausibly first.
pub const FIRST_SAVE: u64 = 1;

// Zero is never a legitimate counter, so an all-zero header reads as wrong rather than as new.
const _: () = assert!(FIRST_SAVE > 0);

/// Reads the save counter without needing the master password.
///
/// Deliberately available before unlocking: whether a vault is older than the last one seen is
/// not a secret, and answering it should not cost a key derivation.
pub fn read_counter(file: &[u8]) -> Result<u64, VaultError> {
    Ok(parse(file)?.counter)
}

/// The parts of a vault file that can be read without the master password.
struct Parsed<'a> {
    header: &'a [u8],
    counter: u64,
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
        counter: read_u64(header, COUNTER_OFFSET),
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
pub fn encode_with(sealing: &SealingKey, counter: u64, body: &[u8]) -> Result<Vec<u8>, VaultError> {
    let header = header_bytes(sealing.params, &sealing.salt, counter);
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

    /// The associated data is no longer redundant, and this records why.
    ///
    /// It used to be: every header field was either a key-derivation input or a constant checked
    /// before the cipher ran, so removing the binding broke no test. The save counter is the
    /// first field that is neither. `rejects_a_tampered_save_counter` above is the one that
    /// fails without it.
    #[test]
    fn no_header_byte_can_be_edited_without_notice() {
        let mut file = encoded();

        for offset in [
            0,
            VERSION_OFFSET,
            COUNTER_OFFSET,
            MEMORY_OFFSET,
            SALT_OFFSET,
        ] {
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
            u64::from_le_bytes(file[COUNTER_OFFSET..COUNTER_OFFSET + 8].try_into().unwrap()),
            FIRST_SAVE
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

        let file = encode_with(&sealing, FIRST_SAVE, BODY).unwrap();

        assert_eq!(decode_with(&sealing, &file).unwrap().as_slice(), BODY);
        // And the password still opens it, because the key is only a cached derivation.
        assert_eq!(decode(PASSWORD, &file).unwrap().as_slice(), BODY);
    }

    #[test]
    fn resealing_keeps_the_salt_and_changes_the_nonce() {
        let sealing = SealingKey::create(PASSWORD, cheap()).unwrap();

        let first = encode_with(&sealing, FIRST_SAVE, BODY).unwrap();
        let second = encode_with(&sealing, FIRST_SAVE, BODY).unwrap();

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
    fn round_trips_a_save_counter() {
        let sealing = SealingKey::create(PASSWORD, cheap()).unwrap();

        let file = encode_with(&sealing, 42, BODY).unwrap();

        assert_eq!(read_counter(&file).unwrap(), 42);
        assert_eq!(decode_with(&sealing, &file).unwrap().as_slice(), BODY);
    }

    #[test]
    fn a_new_vault_starts_at_the_first_save() {
        assert_eq!(read_counter(&encoded()).unwrap(), FIRST_SAVE);
    }

    #[test]
    fn the_save_counter_is_readable_without_the_password() {
        // Whether a vault is older than the last one seen is not a secret, and answering it
        // must not cost an Argon2 derivation before the user has even typed anything.
        assert_eq!(read_counter(&encoded()).unwrap(), FIRST_SAVE);
    }

    #[test]
    fn rejects_a_tampered_save_counter() {
        let file = encode_with(&SealingKey::create(PASSWORD, cheap()).unwrap(), 3, BODY).unwrap();

        let mut raised = file.clone();
        raised[COUNTER_OFFSET..COUNTER_OFFSET + 8].copy_from_slice(&9_999u64.to_le_bytes());

        // This is the test the associated data exists for, and the only one in this module that
        // fails without it. Every other header field is a key-derivation input or a constant
        // compared before the cipher runs; the counter is neither, so nothing else would notice
        // an attacker raising an old vault's counter past the last-seen value.
        assert_eq!(
            decode(PASSWORD, &raised).unwrap_err(),
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
