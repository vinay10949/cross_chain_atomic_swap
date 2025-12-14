use secp256k1::PublicKey;
use sha2::{Digest, Sha256};

/// A message to be signed
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message(pub [u8; 32]);

impl Message {
    pub fn new(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Message(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Message(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Witness value (secret scalar t)
#[derive(Debug, Clone)]
pub struct Witness {
    pub(crate) bytes: [u8; 32],
}

impl Witness {
    pub fn new(bytes: [u8; 32]) -> Self {
        Witness { bytes }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }
}

/// Statement value (public point T = t*G)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub(crate) point: PublicKey,
}

impl Statement {
    pub fn new(point: PublicKey) -> Self {
        Statement { point }
    }

    pub fn as_public_key(&self) -> &PublicKey {
        &self.point
    }
}

/// Partial signature (c, e')
#[derive(Debug, Clone)]
pub struct PartialSignature {
    pub(crate) challenge: [u8; 32],
    pub(crate) response: [u8; 32],
}

impl PartialSignature {
    pub fn new(challenge: [u8; 32], response: [u8; 32]) -> Self {
        PartialSignature {
            challenge,
            response,
        }
    }

    pub fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }

    pub fn response(&self) -> &[u8; 32] {
        &self.response
    }
}

/// Full Schnorr signature (c, e)
#[derive(Debug, Clone)]
pub struct FullSignature {
    pub(crate) challenge: [u8; 32],
    pub(crate) response: [u8; 32],
}

impl FullSignature {
    pub fn new(challenge: [u8; 32], response: [u8; 32]) -> Self {
        FullSignature {
            challenge,
            response,
        }
    }

    pub fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }

    pub fn response(&self) -> &[u8; 32] {
        &self.response
    }

    /// Serialize to 64 bytes (32 bytes challenge + 32 bytes response)
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&self.challenge);
        bytes[32..64].copy_from_slice(&self.response);
        bytes
    }
}
