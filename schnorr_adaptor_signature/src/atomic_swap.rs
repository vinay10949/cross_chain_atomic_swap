use secp256k1::{PublicKey, SecretKey};
use crate::types::{Message, Witness, Statement, PartialSignature, FullSignature};
use crate::adaptor::{self, generate_keypair, generate_witness_statement};
use crate::schnorr;
use crate::error::{Result, AdaptorError};

/// Represents a party in an atomic swap
#[derive(Debug)]
pub struct SwapParty {
    pub name: String,
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

impl SwapParty {
    pub fn new(name: &str) -> Self {
        let (secret_key, public_key) = generate_keypair();
        SwapParty {
            name: name.to_string(),
            secret_key,
            public_key,
        }
    }
}

/// Represents the state of an atomic swap
#[derive(Debug)]
pub struct AtomicSwap {
    pub party_a: SwapParty,
    pub party_b: SwapParty,
    pub party_a_message: Message,
    pub party_b_message: Message,
    pub witness: Option<Witness>,
    pub statement: Option<Statement>,
    pub party_a_partial_sig: Option<PartialSignature>,
    pub party_b_partial_sig: Option<PartialSignature>,
}

impl AtomicSwap {
    /// Initialize a new atomic swap between two parties
    pub fn new(party_a_tx_data: &[u8], party_b_tx_data: &[u8]) -> Self {
        let party_a = SwapParty::new("Party A");
        let party_b = SwapParty::new("Party B");
        let party_a_message = Message::new(party_a_tx_data);
        let party_b_message = Message::new(party_b_tx_data);
        
        AtomicSwap {
            party_a,
            party_b,
            party_a_message,
            party_b_message,
            witness: None,
            statement: None,
            party_a_partial_sig: None,
            party_b_partial_sig: None,
        }
    }
    
    /// Phase 1: Party A generates witness/statement pair
    pub fn party_a_setup(&mut self) -> Statement {
        let (witness, statement) = generate_witness_statement();
        self.witness = Some(witness);
        self.statement = Some(statement.clone());
        statement
    }
    
    /// Phase 2: Party B creates partial signature for their transaction
    /// Party B's transaction will move funds from Party A to Party B on Blockchain #2
    pub fn party_b_create_partial_signature(&mut self, statement: &Statement) -> Result<PartialSignature> {
        let partial_sig = adaptor::pre_sign(
            &self.party_b.secret_key,
            &self.party_b_message,
            statement,
        )?;
        self.party_b_partial_sig = Some(partial_sig.clone());
        Ok(partial_sig)
    }
    
    /// Phase 3: Party A verifies Party B's partial signature
    pub fn party_a_verify_party_b_partial(&self, partial_sig: &PartialSignature) -> Result<bool> {
        let statement = self.statement.as_ref()
            .ok_or(AdaptorError::InvalidSignature)?;
        
        adaptor::pre_verify(
            &self.party_b.public_key,
            &self.party_b_message,
            statement,
            partial_sig,
        )
    }
    
    /// Phase 4: Party A creates and publishes their full signature
    /// This reveals the witness when they publish to Blockchain #1
    pub fn party_a_publish_transaction(&mut self) -> Result<FullSignature> {
        let witness = self.witness.as_ref()
            .ok_or(AdaptorError::InvalidSignature)?;
        let statement = self.statement.as_ref()
            .ok_or(AdaptorError::InvalidSignature)?;
        
        // Party A creates a partial signature first
        let party_a_partial = adaptor::pre_sign(
            &self.party_a.secret_key,
            &self.party_a_message,
            statement,
        )?;
        self.party_a_partial_sig = Some(party_a_partial.clone());
        
        // Then adapts it to a full signature using their witness
        let full_sig = adaptor::adapt(&party_a_partial, witness)?;
        
        // Verify it's a valid Schnorr signature
        let is_valid = schnorr::verify(&self.party_a.public_key, &self.party_a_message, &full_sig)?;
        if !is_valid {
            return Err(AdaptorError::VerificationFailed);
        }
        
        Ok(full_sig)
    }
    
    /// Phase 5: Party B extracts the witness from Party A's published signature
    pub fn party_b_extract_witness(&self, party_a_full_sig: &FullSignature) -> Result<Witness> {
        let party_a_partial = self.party_a_partial_sig.as_ref()
            .ok_or(AdaptorError::InvalidSignature)?;
        
        adaptor::extract(party_a_partial, party_a_full_sig)
    }
    
    /// Phase 6: Party B completes their transaction using the extracted witness
    pub fn party_b_complete_transaction(&self, extracted_witness: &Witness) -> Result<FullSignature> {
        let party_b_partial = self.party_b_partial_sig.as_ref()
            .ok_or(AdaptorError::InvalidSignature)?;
        
        // Party B adapts their partial signature using the extracted witness
        let full_sig = adaptor::adapt(party_b_partial, extracted_witness)?;
        
        // Verify it's a valid Schnorr signature
        let is_valid = schnorr::verify(&self.party_b.public_key, &self.party_b_message, &full_sig)?;
        if !is_valid {
            return Err(AdaptorError::VerificationFailed);
        }
        
        Ok(full_sig)
    }
    
    /// Execute the complete atomic swap protocol
    pub fn execute_swap(&mut self) -> Result<(FullSignature, FullSignature)> {
        // Phase 1: Party A generates witness/statement
        let statement = self.party_a_setup();
        
        // Phase 2: Party B creates partial signature
        let party_b_partial = self.party_b_create_partial_signature(&statement)?;
        
        // Phase 3: Party A verifies Party B's partial signature
        let is_valid = self.party_a_verify_party_b_partial(&party_b_partial)?;
        if !is_valid {
            return Err(AdaptorError::VerificationFailed);
        }
        
        // Phase 4: Party A publishes their transaction (reveals witness)
        let party_a_full_sig = self.party_a_publish_transaction()?;
        
        // Phase 5: Party B extracts witness from Party A's signature
        let extracted_witness = self.party_b_extract_witness(&party_a_full_sig)?;
        
        // Phase 6: Party B completes their transaction
        let party_b_full_sig = self.party_b_complete_transaction(&extracted_witness)?;
        
        Ok((party_a_full_sig, party_b_full_sig))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atomic_swap_complete_flow() {
        // Simulate transaction data for both blockchains
        let party_a_tx = b"Party A sends 1 BTC to Party B on Bitcoin";
        let party_b_tx = b"Party B sends 100 ETH to Party A on Ethereum";
        
        let mut swap = AtomicSwap::new(party_a_tx, party_b_tx);
        
        // Execute the complete swap
        let result = swap.execute_swap();
        assert!(result.is_ok(), "Atomic swap should complete successfully");
        
        let (party_a_sig, party_b_sig) = result.unwrap();
        
        // Verify both signatures are valid
        let party_a_valid = schnorr::verify(
            &swap.party_a.public_key,
            &swap.party_a_message,
            &party_a_sig,
        ).unwrap();
        assert!(party_a_valid, "Party A's signature should be valid");
        
        let party_b_valid = schnorr::verify(
            &swap.party_b.public_key,
            &swap.party_b_message,
            &party_b_sig,
        ).unwrap();
        assert!(party_b_valid, "Party B's signature should be valid");
    }
    
    #[test]
    fn test_witness_extraction() {
        let party_a_tx = b"Transaction A";
        let party_b_tx = b"Transaction B";
        
        let mut swap = AtomicSwap::new(party_a_tx, party_b_tx);
        
        // Setup and create signatures
        let statement = swap.party_a_setup();
        let _ = swap.party_b_create_partial_signature(&statement).unwrap();
        let party_a_full_sig = swap.party_a_publish_transaction().unwrap();
        
        // Party B extracts witness
        let extracted_witness = swap.party_b_extract_witness(&party_a_full_sig).unwrap();
        
        // Verify extracted witness matches original
        let original_witness = swap.witness.as_ref().unwrap();
        assert_eq!(
            extracted_witness.to_bytes(),
            original_witness.to_bytes(),
            "Extracted witness should match original"
        );
    }
}
