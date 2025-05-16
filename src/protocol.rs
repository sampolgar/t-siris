use crate::credential::{Credential, CredentialCommitments};
use crate::errors::{CredentialError, SignatureError};
use crate::keygen::VerificationKeyShare;
use crate::keygen::{keygen, ThresholdKeys, VerificationKey};
use crate::signature::{PartialSignature, ThresholdSignature};
use crate::signer::Signer;
use crate::symmetric_commitment::SymmetricCommitmentKey;
use crate::user::User;
use ark_ec::pairing::Pairing;
use ark_std::{rand::Rng, UniformRand};
use rayon::prelude::*;

pub struct IssuerProtocol;
pub struct UserProtocol;
pub struct VerifierProtocol;

impl IssuerProtocol {
    /// Setup generates the system parameters and keys
    pub fn setup<E: Pairing>(
        threshold: usize,
        num_signers: usize,
        num_attributes: usize,
        rng: &mut impl Rng,
    ) -> (
        SymmetricCommitmentKey<E>,
        VerificationKey<E>,
        ThresholdKeys<E>,
    ) {
        keygen(threshold, num_signers, num_attributes, rng)
    }

    /// Issuer signs a credential request
    pub fn issue_share<E: Pairing>(
        signer: &Signer<E>,
        commitments: &[E::G1Affine],
        commitment_proofs: &[Vec<u8>],
        h: &E::G1Affine,
        rng: &mut impl Rng,
    ) -> Result<PartialSignature<E>, SignatureError> {
        signer.sign_share(commitments, commitment_proofs, h, rng)
    }
}

impl UserProtocol {
    /// User creates a credential request
    pub fn request_credential<E: Pairing>(
        commitment_key: SymmetricCommitmentKey<E>,
        attributes: Option<&[E::ScalarField]>,
        rng: &mut impl Rng,
    ) -> Result<(Credential<E>, CredentialCommitments<E>), CredentialError> {
        let mut credential = Credential::new(commitment_key, attributes, rng);
        let commitments = credential.compute_commitments_per_m(rng)?;
        Ok((credential, commitments))
    }

    // /// User collects signatures from multiple issuers
    // pub fn collect_signature_shares<E: Pairing>(
    //     signers: &[Signer<E>],
    //     credential_request: &CredentialCommitments<E>,
    //     threshold: usize,
    //     rng: &mut impl Rng,
    // ) -> Result<Vec<(usize, PartialSignature<E>)>, SignatureError> {
    //     let mut shares = Vec::new();

    //     // Request signatures from enough signers
    //     for signer in signers.iter().take(threshold) {
    //         let sig_share = signer.sign_share(
    //             &credential_request.commitments,
    //             &credential_request.proofs,
    //             &credential_request.h,
    //             rng,
    //         )?;

    //         shares.push((sig_share.party_index, sig_share));

    //         if shares.len() == threshold {
    //             break;
    //         }
    //     }

    //     // Check if we have enough shares
    //     if shares.len() < threshold {
    //         return Err(SignatureError::InsufficientShares {
    //             needed: threshold,
    //             got: shares.len(),
    //         });
    //     }

    //     Ok(shares)
    // }

    pub fn collect_signature_shares<E: Pairing>(
        signers: &[Signer<E>],
        credential_request: &CredentialCommitments<E>,
        threshold: usize,
        rng: &mut impl Rng,
    ) -> Result<Vec<(usize, PartialSignature<E>)>, SignatureError> {
        let commitments = &credential_request.commitments;
        let proofs = &credential_request.proofs;
        let h = &credential_request.h;

        let shares: Vec<_> = signers
            .par_iter()
            .take(threshold)
            .map(|signer| {
                // Each thread gets its own RNG
                let mut thread_rng = rand::thread_rng();
                signer
                    .sign_share(commitments, proofs, h, &mut thread_rng)
                    .map(|sig_share| (sig_share.party_index, sig_share))
            })
            .collect::<Result<Vec<_>, _>>()?;

        if shares.len() < threshold {
            return Err(SignatureError::InsufficientShares {
                needed: threshold,
                got: shares.len(),
            });
        }

        Ok(shares)
    }

    /// Verify signature shares before aggregation
    pub fn verify_signature_shares<E: Pairing>(
        commitment_key: &SymmetricCommitmentKey<E>,
        vk_shares: &[VerificationKeyShare<E>],
        credential_request: &CredentialCommitments<E>,
        signature_shares: &[(usize, PartialSignature<E>)],
        threshold: usize,
    ) -> Result<Vec<(usize, PartialSignature<E>)>, SignatureError> {
        User::process_signature_shares(
            commitment_key,
            vk_shares,
            &credential_request.commitments,
            &credential_request.proofs,
            signature_shares,
            threshold,
        )
    }

    /// Aggregate signature shares into a complete threshold signature
    pub fn aggregate_shares<E: Pairing>(
        commitment_key: &SymmetricCommitmentKey<E>,
        shares: &[(usize, PartialSignature<E>)],
        blindings: &[E::ScalarField],
        threshold: usize,
        h: &E::G1Affine,
    ) -> Result<ThresholdSignature<E>, SignatureError> {
        ThresholdSignature::aggregate_signature_shares(
            commitment_key,
            shares,
            blindings,
            threshold,
            h,
        )
    }

    /// User shows credential without revealing attributes
    pub fn show<E: Pairing>(
        credential: &Credential<E>,
        rng: &mut impl Rng,
    ) -> Result<(ThresholdSignature<E>, E::G1Affine, E::G2Affine, Vec<u8>), CredentialError> {
        credential.show(rng)
    }
}

impl VerifierProtocol {
    /// Verify a credential presentation
    pub fn verify<E: Pairing>(
        commitment_key: &SymmetricCommitmentKey<E>,
        verification_key: &VerificationKey<E>,
        commitment: &E::G1Affine,
        commitment_tilde: &E::G2Affine,
        signature: &ThresholdSignature<E>,
        proof: &Vec<u8>,
    ) -> Result<bool, SignatureError> {
        ThresholdSignature::<E>::verify(
            commitment_key,
            verification_key,
            commitment,
            commitment_tilde,
            signature,
            proof,
        )
    }
}
