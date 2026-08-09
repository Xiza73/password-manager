//! The wrapper every secret in this application lives in.
//!
//! Sits below both `crypto` and `vault` because both need it, and neither should have to reach
//! through the other to get it.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A string that wipes itself when dropped and never renders its contents.
///
/// `String` is the wrong type for a password: it has a derived `Debug`, it serializes freely, and
/// it leaves its bytes on the heap when dropped. This wrapper closes all three.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Reveals the secret. Named to stand out in review, like `MasterKey::expose`.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No length, either: the length of a password is worth something to an attacker.
        f.write_str("SecretString(<redacted>)")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
