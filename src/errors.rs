use ark_serialize::SerializationError;
use thiserror::Error;

/// Errors that can occur during commitment operations
#[derive(Error, Debug)]
pub enum CommitmentError {
    #[error("Invalid commitment computation")]
    InvalidComputeCommitment,

    #[error("Invalid commitment")]
    InvalidCommitment,

    #[error("Invalid proof")]
    InvalidProof,

    #[error("Serialization error: {0}")]
    SerializationError(#[from] SerializationError),

    #[error("Proof verification failed")]
    ProofVerificationFailed,

    #[error("Batch Proof verification failed")]
    BatchVerifyError,
}

/// Errors that can occur during signature operations
#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("Serialization error: {0}")]
    SerializationError(#[from] SerializationError),

    #[error("Commitment error: {0}")]
    CommitmentError(#[from] CommitmentError),

    #[error("Invalid signature share from party {0}")]
    InvalidShare(usize),

    #[error("Duplicate signature share from party {0}")]
    DuplicateShare(usize),

    #[error("Threshold requirement not met")]
    ThresholdNotMet,

    #[error("Insufficient signature shares, needed {needed}, got {got}")]
    InsufficientShares { needed: usize, got: usize },

    #[error("Proof error: {0}")]
    ProofError(String),

    #[error("User error: {0}")]
    UserError(String),

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Commitment consistency check failed")]
    CommitmentConsistencyFailed,

    #[error("Invalid credential state: {0}")]
    InvalidState(String),
}

/// Errors that can occur during protocol operations
#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Signature error: {0}")]
    SignatureError(#[from] SignatureError),

    // #[error("Verification error: {0}")]
    // VerificationError(#[from] SignatureError),
    #[error("Commitment error: {0}")]
    CommitmentError(#[from] CommitmentError),

    #[error("Invalid protocol state: {0}")]
    InvalidState(String),

    #[error("User error: {0}")]
    UserError(String),
}

#[derive(Error, Debug)]
pub enum CredentialError {
    #[error("Missing signature: {0}")]
    MissingSignature(String),
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(#[from] CommitmentError),
    #[error("Signature randomization failed: {0}")]
    RandomizationFailed(String),
    #[error("Invalid credential state: {0}")]
    InvalidState(String),
}
