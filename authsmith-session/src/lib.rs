//! # authsmith-session
//!
//! Session token generation implementing the [`authsmith_core::TokenGenerator`] trait,
//! plus session expiry and rotation helpers.
//!
//! ## Usage
//!
//! ```rust
//! use authsmith_session::SecureTokenGenerator;
//! use authsmith_core::TokenGenerator;
//!
//! let gen = SecureTokenGenerator::default();
//! let token = gen.generate();
//! assert_eq!(token.len(), 43); // 32 bytes base64url, no padding
//! ```

use authsmith_core::TokenGenerator;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;

// ── Token generator ───────────────────────────────────────────────────────────

/// Generates cryptographically random session tokens.
///
/// Each token is 32 random bytes encoded as base64url without padding (43 chars).
/// Store and transmit the string; compare with constant-time equality.
#[derive(Debug, Clone)]
pub struct SecureTokenGenerator {
    /// Number of random bytes per token. Default: 32 (256 bits).
    byte_len: usize,
}

impl SecureTokenGenerator {
    /// Create a generator using `byte_len` bytes of entropy per token.
    ///
    /// 32 bytes (default) gives 256 bits — far beyond any brute-force attack.
    pub fn new(byte_len: usize) -> Self {
        Self { byte_len }
    }
}

impl Default for SecureTokenGenerator {
    fn default() -> Self {
        Self { byte_len: 32 }
    }
}

impl TokenGenerator for SecureTokenGenerator {
    /// Produce a cryptographically secure random base64url token (no padding).
    fn generate(&self) -> String {
        let mut bytes = vec![0u8; self.byte_len];
        rand::rng().fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(&bytes)
    }
}

// ── Session expiry helpers ────────────────────────────────────────────────────

/// Returns the Unix timestamp (seconds) at which a session created right now
/// should expire, given a TTL in seconds.
///
/// Uses `std::time::SystemTime` — no tokio dependency.
pub fn expiry_from_ttl(ttl_secs: i64) -> i64 {
    now_secs() + ttl_secs
}

/// Returns the current Unix timestamp in seconds.
pub fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ── Token comparison ──────────────────────────────────────────────────────────

/// Compare two token strings in constant time to prevent timing attacks.
///
/// Use this instead of `==` when checking session tokens.
pub fn tokens_equal(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use authsmith_core::TokenGenerator;

    #[test]
    fn token_is_43_chars_for_32_bytes() {
        let gen = SecureTokenGenerator::default();
        let t = gen.generate();
        // 32 bytes → ceil(32*4/3) = 43 chars (base64url, no padding)
        assert_eq!(t.len(), 43);
    }

    #[test]
    fn tokens_are_unique() {
        let gen = SecureTokenGenerator::default();
        let a = gen.generate();
        let b = gen.generate();
        assert_ne!(a, b);
    }

    #[test]
    fn token_is_url_safe() {
        let gen = SecureTokenGenerator::default();
        for _ in 0..20 {
            let t = gen.generate();
            assert!(
                t.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
                "token contained non-URL-safe character: {t}"
            );
        }
    }

    #[test]
    fn constant_time_compare() {
        assert!(tokens_equal("abc", "abc"));
        assert!(!tokens_equal("abc", "abd"));
        assert!(!tokens_equal("abc", "abcd"));
    }

    #[test]
    fn expiry_is_in_the_future() {
        let before = now_secs();
        let expiry = expiry_from_ttl(3600);
        assert!(expiry > before);
        assert!(expiry <= before + 3600 + 1);
    }
}
