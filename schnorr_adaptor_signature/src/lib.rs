//! # Schnorr Adaptor Signatures & Atomic Swaps
//!
//! This library implements Schnorr adaptor signatures and atomic swap protocols
//! based on the discrete logarithm problem on elliptic curves.
//!
//! ## Overview
//!
//! An adaptor signature is a two-step signing scheme where:
//! 1. A partial signature is created that's bound to a secret witness
//! 2. The partial signature can be adapted to a full signature using the witness
//! 3. The witness can be extracted from both the partial and full signatures
//!
//! This enables trustless atomic swaps between two parties on different blockchains.
pub mod error;
pub mod types;
pub mod schnorr;
pub mod adaptor;
pub mod atomic_swap;