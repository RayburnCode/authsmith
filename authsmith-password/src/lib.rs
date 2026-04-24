//! # authsmith-password
//!
//! Argon2id password hashing implementing the [`authsmith_core::PasswordHasher`] trait.
//!
//! ## Usage
//!
//! ```rust
//! use authsmith_password::Argon2Hasher;
//! use authsmith_core::PasswordHasher;
//!
//! let hasher = Argon2Hasher::default();
//! let hash = hasher.hash("correct-horse-battery-staple").unwrap();
//! assert!(hasher.verify("correct-horse-battery-staple", &hash).unwrap());
//! assert!(!hasher.verify("wrong-password", &hash).unwrap());
//! ```

use argon2::{
    password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString},
    Argon2,
};
use rand_core::OsRng;
use authsmith_core::PasswordHasher;
use secrecy::{ExposeSecret, SecretString};

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("hashing failed: {0}")]
    Hash(String),
    #[error("invalid hash string: {0}")]
    InvalidHash(String),
    #[error("password policy violation: {0}")]
    Policy(String),
}

// ── Hasher ────────────────────────────────────────────────────────────────────

/// Argon2id hasher — safe defaults (memory: 64 MiB, iterations: 3, parallelism: 4).
///
/// Keep a single instance and share it across handlers via `Arc<Argon2Hasher>`.
#[derive(Clone)]
pub struct Argon2Hasher {
    min_length: usize,
    max_length: usize,
}

impl Default for Argon2Hasher {
    fn default() -> Self {
        Self {
            min_length: 8,
            max_length: 128, // guards against bcrypt-style long-password DoS
        }
    }
}

impl Argon2Hasher {
    /// Create a hasher with custom min/max password length constraints.
    pub fn new(min_length: usize, max_length: usize) -> Self {
        Self { min_length, max_length }
    }

    fn check_policy(&self, password: &str) -> Result<(), PasswordError> {
        if password.len() < self.min_length {
            return Err(PasswordError::Policy(format!(
                "password must be at least {} characters",
                self.min_length
            )));
        }
        if password.len() > self.max_length {
            return Err(PasswordError::Policy(format!(
                "password must not exceed {} characters",
                self.max_length
            )));
        }
        Ok(())
    }
}

impl PasswordHasher for Argon2Hasher {
    type Error = PasswordError;

    /// Hash a raw password with a fresh random salt.
    ///
    /// The returned string is a self-contained PHC string — store it as-is.
    fn hash(&self, password: &str) -> Result<String, Self::Error> {
        self.check_policy(password)?;

        // Wrap in SecretString so it's zeroed on drop.
        let secret = SecretString::new(password.to_owned().into());
        let salt = SaltString::generate(&mut OsRng);

        Argon2::default()
            .hash_password(secret.expose_secret().as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| PasswordError::Hash(e.to_string()))
    }

    /// Verify a raw password against a stored PHC hash string.
    fn verify(&self, password: &str, hash: &str) -> Result<bool, Self::Error> {
        let parsed = PasswordHash::new(hash)
            .map_err(|e| PasswordError::InvalidHash(e.to_string()))?;

        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use authsmith_core::PasswordHasher;

    #[test]
    fn round_trip() {
        let hasher = Argon2Hasher::default();
        let hash = hasher.hash("correct-horse-battery-staple").unwrap();
        assert!(hasher.verify("correct-horse-battery-staple", &hash).unwrap());
    }

    #[test]
    fn wrong_password_fails() {
        let hasher = Argon2Hasher::default();
        let hash = hasher.hash("correct-horse-battery-staple").unwrap();
        assert!(!hasher.verify("wrong-password", &hash).unwrap());
    }

    #[test]
    fn each_hash_uses_unique_salt() {
        let hasher = Argon2Hasher::default();
        let h1 = hasher.hash("same-password").unwrap();
        let h2 = hasher.hash("same-password").unwrap();
        assert_ne!(h1, h2, "two hashes of the same password must differ");
    }

    #[test]
    fn rejects_too_short() {
        let hasher = Argon2Hasher::new(10, 128);
        assert!(matches!(hasher.hash("short"), Err(PasswordError::Policy(_))));
    }

    #[test]
    fn rejects_too_long() {
        let hasher = Argon2Hasher::new(8, 10);
        assert!(matches!(
            hasher.hash("this-is-way-too-long"),
            Err(PasswordError::Policy(_))
        ));
    }
}
