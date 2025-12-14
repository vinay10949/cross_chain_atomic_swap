use secp256k1::{PublicKey, SecretKey, SECP256K1};
use sha2::{Sha256, Digest};
use crate::types::{Message, Witness, Statement, PartialSignature, FullSignature};
use crate::error::{Result, AdaptorError};
use secp256k1::rand::rng;

/// Generate a random keypair
pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let secp = SECP256K1;
    let mut rng = rng();
    secp.generate_keypair(&mut rng)
}

/// Generate a witness/statement pair for the discrete log relation
/// Returns (witness t, statement T = t*G)
pub fn generate_witness_statement() -> (Witness, Statement) {
    let secp = SECP256K1;
    let mut rng = rng();
    let (secret, public) = secp.generate_keypair(&mut rng);
    
    let witness = Witness::new(secret.secret_bytes());
    let statement = Statement::new(public);
    
    (witness, statement)
}

/// PreSign: Create a partial signature
/// 
/// Algorithm:
/// 1. Generate random nonce r, compute R = r*G
/// 2. Compute c = H(X || R + T || m)
/// 3. Compute e' = r + c*x (mod n)
/// 
/// Returns partial signature (c, e')
pub fn pre_sign(
    secret_key: &SecretKey,
    message: &Message,
    statement: &Statement,
) -> Result<PartialSignature> {
    let secp = SECP256K1;
    let mut rng = rng();
    // Generate random nonce r
    let (nonce_secret, nonce_public) = secp.generate_keypair(&mut rng);
    
    // Get public key X from secret key x
    let public_key = secret_key.public_key(secp);
    
    // Compute R + T
    let r_plus_t = nonce_public.combine(statement.as_public_key())?;
    
    // Compute c = H(X || R + T || m)
    let challenge = compute_challenge_with_statement(&public_key, &r_plus_t, message);
    
    // Compute e' = r + c*x (mod n)
    let e_prime = scalar_add_mul(&nonce_secret, &challenge, secret_key)?;
    
    Ok(PartialSignature::new(challenge, e_prime))
}

/// PreVerify: Verify a partial signature
/// 
/// Algorithm:
/// 1. Compute R' = e'*G - c*X
/// 2. Compute c' = H(X || R' + T || m)
/// 3. Check if c' == c
pub fn pre_verify(
    public_key: &PublicKey,
    message: &Message,
    statement: &Statement,
    partial_sig: &PartialSignature,
) -> Result<bool> {
    let secp = SECP256K1;
    
    // Compute R' = e'*G - c*X
    let e_prime_key = SecretKey::from_byte_array(partial_sig.response)?;
    let e_prime_g = e_prime_key.public_key(secp);
    
    let c_key = SecretKey::from_byte_array(partial_sig.challenge)?;
    let c_x = public_key.mul_tweak(secp, &c_key.into())?;
    let neg_c_x = c_x.negate(secp);
    
    let r_prime = e_prime_g.combine(&neg_c_x)?;
    
    // Compute R' + T
    let r_prime_plus_t = r_prime.combine(statement.as_public_key())?;
    
    // Compute c' = H(X || R' + T || m)
    let challenge_prime = compute_challenge_with_statement(public_key, &r_prime_plus_t, message);
    
    // Check if c' == c
    Ok(challenge_prime == partial_sig.challenge)
}

/// Adapt: Convert partial signature to full signature using witness
/// 
/// Algorithm:
/// e = e' + t (mod n)
/// 
/// Returns full signature (c, e)
pub fn adapt(
    partial_sig: &PartialSignature,
    witness: &Witness,
) -> Result<FullSignature> {
    // Compute e = e' + t (mod n)
    let e_prime_key = SecretKey::from_byte_array(partial_sig.response)?;
    let witness_key = SecretKey::from_byte_array(witness.bytes)?;
    let e = e_prime_key.add_tweak(&witness_key.into())?;
    
    Ok(FullSignature::new(partial_sig.challenge, e.secret_bytes()))
}

/// Extract: Recover witness from partial and full signatures
/// 
/// Algorithm:
/// t = e - e' (mod n)
pub fn extract(
    partial_sig: &PartialSignature,
    full_sig: &FullSignature,
) -> Result<Witness> {
    // Verify that both signatures have the same challenge
    if partial_sig.challenge != full_sig.challenge {
        return Err(AdaptorError::InvalidSignature);
    }
    
    // Compute t = e - e' (mod n)
    let e_key = SecretKey::from_byte_array(full_sig.response)?;
    let e_prime_key = SecretKey::from_byte_array(partial_sig.response)?;
    
    // Negate e' and add to e
    let neg_e_prime = e_prime_key.negate();
    let t = e_key.add_tweak(&neg_e_prime.into())?;
    
    Ok(Witness::new(t.secret_bytes()))
}

/// Helper: Compute a + b*c (mod n) for scalars
fn scalar_add_mul(a: &SecretKey, b: &[u8; 32], c: &SecretKey) -> Result<[u8; 32]> {
    let b_key = SecretKey::from_byte_array(*b)?;
    let b_times_c = c.mul_tweak(&b_key.into())?;
    let result = a.add_tweak(&b_times_c.into())?;
    Ok(result.secret_bytes())
}

/// Compute challenge c = H(X || R || m) where R includes the statement
fn compute_challenge_with_statement(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schnorr;

    #[test]
    fn test_adaptor_signature_flow() {
        // Setup: Party A generates witness/statement, Party B generates keypair
        let (witness, statement) = generate_witness_statement();
        let (party_b_secret, party_b_public) = generate_keypair();
        let message = Message::new(b"Hello, Adaptor Signatures!");

        // PreSign: Party B creates partial signature
        let partial_sig = pre_sign(&party_b_secret, &message, &statement).unwrap();

        // PreVerify: Party A verifies the partial signature
        let is_valid = pre_verify(&party_b_public, &message, &statement, &partial_sig).unwrap();
        assert!(is_valid, "Partial signature should be valid");

        // Adapt: Party A adapts to full signature using their witness
        let full_sig = adapt(&partial_sig, &witness).unwrap();

        // Verify: Full signature should verify as a valid Schnorr signature
        let is_schnorr_valid = schnorr::verify(&party_b_public, &message, &full_sig).unwrap();
        assert!(is_schnorr_valid, "Full signature should be valid Schnorr signature");

        // Extract: Party B extracts the witness from both signatures
        let extracted_witness = extract(&partial_sig, &full_sig).unwrap();
        
        // Verify extracted witness matches original
        assert_eq!(
            extracted_witness.to_bytes(),
            witness.to_bytes(),
            "Extracted witness should match original"
        );
    }
}
