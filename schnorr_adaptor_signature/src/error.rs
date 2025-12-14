use thiserror::Error;

#[derive(Error, Debug)]
pub enum AdaptorError {
    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Verification failed")]
    VerificationFailed,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid secret key")]
    InvalidSecretKey,

    #[error("Secp256k1 error: {0}")]
    Secp256k1Error(#[from] secp256k1::Error),
}

pub type Result<T> = std::result::Result<T, AdaptorError>;
