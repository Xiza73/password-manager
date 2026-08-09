//! Authenticated encryption of the vault body with AES-256-GCM.
//!
//! GCM is an AEAD: it does not only hide the plaintext, it detects any modification of the
//! ciphertext, the nonce, or the associated data. That detection is what makes it safe to leave
//! the vault file somewhere an attacker can write to it, not merely read it.

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::Aes256Gcm;
use rand::rngs::SysRng;
use rand::TryRng;
use zeroize::Zeroizing;

use crate::crypto::kdf::MasterKey;

/// Nonce length in bytes. 96 bits is the size GCM is defined for; other sizes go through an
/// extra derivation step and buy nothing.
pub const NONCE_LEN: usize = 12;

/// Authentication tag length in bytes. Truncating the tag weakens forgery resistance, so it
/// stays at the full 128 bits.
pub const TAG_LEN: usize = 16;

/// Failures are deliberately coarse.
///
/// There is a single variant for every way authentication can fail — wrong key, flipped bit,
/// swapped nonce, mismatched associated data, truncation. Telling those apart would tell an
/// attacker which knob they moved, and none of the distinctions help a legitimate caller: the
/// answer is always "this data is not authentic, refuse it".
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CipherError {
    #[error("the system random number generator is unavailable")]
    RandomUnavailable,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("the data could not be authenticated")]
    Unauthentic,
}

/// A single-use number. Not secret — it is stored beside the ciphertext — but it must never
/// repeat under the same key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    /// Draws a fresh nonce from the operating system's CSPRNG.
    ///
    /// Random 96-bit nonces collide with probability ~2^-32 after 2^32 messages under one key.
    /// A vault is resealed once per save, so that bound is many orders of magnitude beyond any
    /// real usage — but it is the reason a counter would be wrong here: a counter that resets
    /// after a restore from backup repeats, and repetition is fatal in GCM.
    pub fn generate() -> Result<Self, CipherError> {
        let mut bytes = [0u8; NONCE_LEN];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| CipherError::RandomUnavailable)?;

        Ok(Self(bytes))
    }

    pub const fn from_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

/// A sealed payload: the nonce it was sealed with, and the ciphertext with its tag appended.
///
/// Both parts are safe to persist in the clear. Neither is safe to modify — `open` will refuse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBox {
    nonce: Nonce,
    ciphertext: Vec<u8>,
}

impl SealedBox {
    /// Rebuilds a sealed payload read back from disk.
    ///
    /// No validation happens here on purpose. Whether the bytes are genuine is not a question
    /// this constructor can answer — only `open` can, by checking the tag.
    pub const fn from_parts(nonce: Nonce, ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }

    pub const fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// Encrypts and authenticates `plaintext`, binding `aad` to the result.
///
/// `aad` is authenticated but not encrypted. Passing the vault header here is what stops an
/// attacker editing the header — downgrading the KDF cost, say — while leaving the body intact.
pub fn seal(key: &MasterKey, plaintext: &[u8], aad: &[u8]) -> Result<SealedBox, CipherError> {
    let cipher = Aes256Gcm::new(key.expose().into());
    let nonce = Nonce::generate()?;

    // Not `Zeroizing`, and deliberately so: `encrypt_in_place` overwrites the plaintext with
    // ciphertext in the same allocation, so nothing sensitive survives the call. The capacity is
    // exact to avoid a reallocation, which would leave a copy of the plaintext on the heap that
    // nothing can reach to wipe.
    let mut buffer = Vec::with_capacity(plaintext.len() + TAG_LEN);
    buffer.extend_from_slice(plaintext);

    cipher
        .encrypt_in_place(nonce.as_bytes().into(), aad, &mut buffer)
        .map_err(|_| CipherError::EncryptionFailed)?;

    Ok(SealedBox {
        nonce,
        ciphertext: buffer,
    })
}

/// Verifies and decrypts a sealed payload.
///
/// The plaintext comes back in a `Zeroizing` buffer: this is credential material, and letting it
/// sit in a plain `Vec` until the allocator happens to reuse the pages is exactly the leak this
/// application exists to prevent.
pub fn open(
    key: &MasterKey,
    sealed: &SealedBox,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CipherError> {
    let cipher = Aes256Gcm::new(key.expose().into());

    // Held in `Zeroizing` from the start. AES-GCM verifies the tag in constant time *before*
    // decrypting, so a rejected payload never becomes plaintext here — but a successful one
    // does, and it must not outlive this value.
    let mut buffer = Zeroizing::new(sealed.ciphertext.clone());

    cipher
        .decrypt_in_place(sealed.nonce.as_bytes().into(), aad, &mut *buffer)
        .map_err(|_| CipherError::Unauthentic)?;

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::{derive_key, KdfParams, Salt, SALT_LEN};

    const AAD: &[u8] = b"vault-header-v1";
    const PLAINTEXT: &[u8] = b"github.com\0octocat\0hunter2";

    fn key_from(password: &[u8]) -> MasterKey {
        derive_key(
            password,
            &Salt::from_bytes([0x11; SALT_LEN]),
            KdfParams::new(8, 1, 1).expect("cheap test parameters must be valid"),
        )
        .expect("derivation must succeed")
    }

    fn flip_bit(bytes: &mut [u8], index: usize) {
        bytes[index] ^= 0b0000_0001;
    }

    #[test]
    fn round_trips_a_plaintext() {
        let key = key_from(b"master");

        let sealed = seal(&key, PLAINTEXT, AAD).unwrap();
        let opened = open(&key, &sealed, AAD).unwrap();

        assert_eq!(opened.as_slice(), PLAINTEXT);
    }

    #[test]
    fn round_trips_an_empty_plaintext() {
        let key = key_from(b"master");

        let sealed = seal(&key, b"", AAD).unwrap();
        let opened = open(&key, &sealed, AAD).unwrap();

        assert!(opened.is_empty());
    }

    #[test]
    fn round_trips_without_associated_data() {
        let key = key_from(b"master");

        let sealed = seal(&key, PLAINTEXT, b"").unwrap();
        let opened = open(&key, &sealed, b"").unwrap();

        assert_eq!(opened.as_slice(), PLAINTEXT);
    }

    #[test]
    fn rejects_a_wrong_key() {
        let sealed = seal(&key_from(b"master"), PLAINTEXT, AAD).unwrap();

        let result = open(&key_from(b"not the master"), &sealed, AAD);

        assert_eq!(result.unwrap_err(), CipherError::Unauthentic);
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let key = key_from(b"master");
        let sealed = seal(&key, PLAINTEXT, AAD).unwrap();

        let mut bytes = sealed.ciphertext().to_vec();
        flip_bit(&mut bytes, 0);
        let tampered = SealedBox::from_parts(*sealed.nonce(), bytes);

        assert_eq!(
            open(&key, &tampered, AAD).unwrap_err(),
            CipherError::Unauthentic
        );
    }

    #[test]
    fn rejects_a_tampered_tag() {
        let key = key_from(b"master");
        let sealed = seal(&key, PLAINTEXT, AAD).unwrap();

        let mut bytes = sealed.ciphertext().to_vec();
        let last = bytes.len() - 1;
        flip_bit(&mut bytes, last);
        let tampered = SealedBox::from_parts(*sealed.nonce(), bytes);

        assert_eq!(
            open(&key, &tampered, AAD).unwrap_err(),
            CipherError::Unauthentic
        );
    }

    #[test]
    fn rejects_a_tampered_nonce() {
        let key = key_from(b"master");
        let sealed = seal(&key, PLAINTEXT, AAD).unwrap();

        let mut nonce_bytes = *sealed.nonce().as_bytes();
        flip_bit(&mut nonce_bytes, 0);
        let tampered =
            SealedBox::from_parts(Nonce::from_bytes(nonce_bytes), sealed.ciphertext().to_vec());

        assert_eq!(
            open(&key, &tampered, AAD).unwrap_err(),
            CipherError::Unauthentic
        );
    }

    #[test]
    fn rejects_mismatched_associated_data() {
        let key = key_from(b"master");
        let sealed = seal(&key, PLAINTEXT, AAD).unwrap();

        // This is what stops an attacker swapping the vault header — downgrading the KDF cost,
        // say — while leaving the encrypted body untouched.
        let result = open(&key, &sealed, b"vault-header-v0");

        assert_eq!(result.unwrap_err(), CipherError::Unauthentic);
    }

    #[test]
    fn rejects_truncated_ciphertext() {
        let key = key_from(b"master");
        let sealed = seal(&key, PLAINTEXT, AAD).unwrap();

        let mut bytes = sealed.ciphertext().to_vec();
        bytes.truncate(bytes.len() - 1);
        let truncated = SealedBox::from_parts(*sealed.nonce(), bytes);

        assert_eq!(
            open(&key, &truncated, AAD).unwrap_err(),
            CipherError::Unauthentic
        );
    }

    #[test]
    fn rejects_ciphertext_shorter_than_the_tag() {
        let key = key_from(b"master");

        let stub = SealedBox::from_parts(Nonce::generate().unwrap(), vec![0u8; TAG_LEN - 1]);

        assert_eq!(
            open(&key, &stub, AAD).unwrap_err(),
            CipherError::Unauthentic
        );
    }

    #[test]
    fn uses_a_fresh_nonce_for_every_seal() {
        let key = key_from(b"master");

        let first = seal(&key, PLAINTEXT, AAD).unwrap();
        let second = seal(&key, PLAINTEXT, AAD).unwrap();

        // Reusing a nonce with the same key in GCM leaks the XOR of the plaintexts and the
        // authentication subkey. It is the one mistake this construction cannot survive.
        assert_ne!(first.nonce(), second.nonce());
    }

    #[test]
    fn seals_the_same_plaintext_to_different_ciphertext() {
        let key = key_from(b"master");

        let first = seal(&key, PLAINTEXT, AAD).unwrap();
        let second = seal(&key, PLAINTEXT, AAD).unwrap();

        assert_ne!(first.ciphertext(), second.ciphertext());
    }

    #[test]
    fn ciphertext_does_not_contain_the_plaintext() {
        let key = key_from(b"master");

        let sealed = seal(&key, PLAINTEXT, AAD).unwrap();

        assert!(!sealed
            .ciphertext()
            .windows(PLAINTEXT.len())
            .any(|window| window == PLAINTEXT));
    }

    #[test]
    fn ciphertext_is_the_plaintext_length_plus_the_tag() {
        let key = key_from(b"master");

        let sealed = seal(&key, PLAINTEXT, AAD).unwrap();

        assert_eq!(sealed.ciphertext().len(), PLAINTEXT.len() + TAG_LEN);
    }

    #[test]
    fn every_failure_mode_reports_the_same_error() {
        let key = key_from(b"master");
        let sealed = seal(&key, PLAINTEXT, AAD).unwrap();

        let mut flipped = sealed.ciphertext().to_vec();
        flip_bit(&mut flipped, 0);
        let mut truncated = sealed.ciphertext().to_vec();
        truncated.truncate(TAG_LEN);

        // An attacker must not learn *which* knob they moved. One opaque failure, always.
        let failures = [
            open(&key_from(b"wrong"), &sealed, AAD).unwrap_err(),
            open(&key, &SealedBox::from_parts(*sealed.nonce(), flipped), AAD).unwrap_err(),
            open(
                &key,
                &SealedBox::from_parts(*sealed.nonce(), truncated),
                AAD,
            )
            .unwrap_err(),
            open(&key, &sealed, b"different aad").unwrap_err(),
        ];

        for failure in failures {
            assert_eq!(failure, CipherError::Unauthentic);
            assert_eq!(failure.to_string(), CipherError::Unauthentic.to_string());
        }
    }

    #[test]
    fn generated_nonces_differ() {
        assert_ne!(Nonce::generate().unwrap(), Nonce::generate().unwrap());
    }

    #[test]
    fn nonce_round_trips_through_bytes() {
        let bytes = [0x5Au8; NONCE_LEN];

        assert_eq!(Nonce::from_bytes(bytes).as_bytes(), &bytes);
    }

    #[test]
    fn error_messages_do_not_mention_secrets() {
        for error in [
            CipherError::RandomUnavailable,
            CipherError::EncryptionFailed,
            CipherError::Unauthentic,
        ] {
            let message = error.to_string().to_lowercase();

            assert!(!message.is_empty());
            assert!(!message.contains("password"));
            assert!(!message.contains("plaintext"));
        }
    }
}
