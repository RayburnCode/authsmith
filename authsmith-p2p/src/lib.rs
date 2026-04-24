//! # authsmith-p2p
//!
//! libp2p keypair peer identity for AuthSmith.
//!
//! Enables decentralised user identity alongside (or instead of) traditional
//! email/password login — users are identified by their libp2p `PeerId`.
//!
//! ## Use case (DSCR Express)
//!
//! - Each client generates a local keypair on first launch.
//! - The `PeerId` (derived from the public key) is stored in `AuthUser::peer_id`.
//! - Peers prove ownership by signing a challenge with their private key.
//! - The signaling layer (Cloudflare Workers) uses the `PeerId` to route WebRTC
//!   offers/answers without a central identity server.
//!
//! ## Status
//! **Planned** — types and trait API are defined; libp2p integration coming in v0.4.

use authsmith_core::AuthUser;
use serde::{Deserialize, Serialize};

// ── Types ─────────────────────────────────────────────────────────────────────

/// A libp2p `PeerId` represented as its canonical base58btc string.
///
/// Example: `12D3KooWEyoppNCUx8Yx66oV9fJnriXwCZXaWNqSYkCdekbFHMaE`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub String);

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A challenge issued to a peer to prove keypair ownership.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerChallenge {
    /// Random nonce — the peer must sign this exact bytes.
    pub nonce: String,
    /// Unix timestamp after which this challenge is no longer valid.
    pub expires_at: i64,
}

/// A signed challenge response from a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerChallengeResponse {
    pub peer_id: PeerId,
    pub nonce: String,
    /// Signature over the nonce bytes using the peer's private key.
    pub signature: Vec<u8>,
}

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum P2pAuthError {
    #[error("challenge expired")]
    ChallengeExpired,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("peer not found: {0}")]
    PeerNotFound(String),
    #[error("key parsing failed: {0}")]
    KeyParse(String),
}

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Implement this to plug in libp2p keypair authentication.
///
/// The concrete implementation will be provided in `authsmith-p2p` v0.4 once
/// the `libp2p` feature flag is active.
#[async_trait::async_trait]
pub trait P2pAuthProvider: Send + Sync {
    /// Issue a fresh challenge for the given peer.
    async fn issue_challenge(&self, peer_id: &PeerId) -> Result<PeerChallenge, P2pAuthError>;

    /// Verify a signed challenge response and return the matching [`AuthUser`].
    ///
    /// Creates a new user account if no user with the given `peer_id` exists.
    async fn verify_challenge(
        &self,
        response: PeerChallengeResponse,
    ) -> Result<AuthUser, P2pAuthError>;
}
