use secp256k1::{PublicKey, SecretKey, SECP256K1};
use sha2::{Sha256, Digest};
use crate::types::{Message, FullSignature};
use crate::error::Result;

/// Verify a full Schnorr signature
/// 
/// Verification algorithm:
/// 1. Compute R = e*G - c*X
/// 2. Compute c' = H(X || R || m)
/// 3. Check if c' == c
pub fn verify(
    public_key: &PublicKey,
    message: &Message,
    signature: &FullSignature,
) -> Result<bool> {
    let secp = SECP256K1;
    
    // Convert response bytes to SecretKey for scalar multiplication
    let e_key = SecretKey::from_byte_array(signature.response)?;
    let e_g = e_key.public_key(secp);
    
    // Compute -c*X by negating the challenge
    let c_key = SecretKey::from_byte_array(signature.challenge)?;
    let c_x = public_key.mul_tweak(secp, &c_key.into())?;
    let neg_c_x = c_x.negate(secp);
    
    // Compute R = e*G + (-c*X)
    let r_point = e_g.combine(&neg_c_x)?;
    
    // Compute c' = H(X || R || m)
    let challenge_prime = compute_challenge(public_key, &r_point, message);
    
    // Check if c' == c
    Ok(challenge_prime == signature.challenge)
}

/// Compute challenge c = H(X || R || m)
pub(crate) fn compute_challenge(
    public_key: &PublicKey,
    r_point: &PublicKey,
    message: &Message,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(public_key.serialize());
    hasher.update(r_point.serialize());
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();
    
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}
