use crate::commitment::batch_verify;
use crate::errors::{CommitmentError, SignatureError};
use crate::keygen::VerificationKeyShare;
use crate::pairing::verify_pairing_equation;
use crate::signature::PartialSignature;
use crate::symmetric_commitment::SymmetricCommitmentKey;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_std::ops::Neg;
use ark_std::rand::Rng;

pub struct User;
impl User {
    /// Verify a signature share received from a signer
    /// This implements RS.ShareVer in the protocol
    pub fn verify_signature_share<E: Pairing>(
        commitment_key: &SymmetricCommitmentKey<E>,
        vk_share: &VerificationKeyShare<E>,
        commitments: &[E::G1Affine],
        commitment_proofs: &[Vec<u8>],
        sig_share: &PartialSignature<E>,
        rng: &mut impl Rng,
    ) -> Result<bool, SignatureError> {
        // 1. First verify the ZKPs for each commitment
        // We can use the optimised version of batch_verify
        // let timer_start = std::time::Instant::now();
        let valid = batch_verify::<E>(commitment_proofs, rng)?;
        if !valid {
            return Err(CommitmentError::BatchVerifyError.into());
        }
        // let elapsed = timer_start.elapsed();

        // println!("Batch verify time: {:?}", elapsed);

        // for (_, proof) in commitments.iter().zip(commitment_proofs.iter()) {
        //     let is_valid =
        //         Commitment::<E>::verify(proof).map_err(|e| SignatureError::CommitmentError(e))?;

        //     if !is_valid {
        //         return Ok(false);
        //     }
        // }

        // 2. Verify the signature share using the pairing equation
        // e([σ*]_i,2, g̃) = e(h, g̃^[x]_i) · ∏_{k∈[ℓ]} e(cm_k, g̃^[y_k]_i)

        let mut pairs = Vec::new();

        // e(-sigma_i, g̃) = e([σ*]_i,2, g̃)^(-1)
        let neg_sigma_i = sig_share.sigma.into_group().neg().into_affine();
        pairs.push((&neg_sigma_i, &commitment_key.g_tilde));

        // e(h, g̃^[x]_i)
        pairs.push((&sig_share.h, &vk_share.g_tilde_x_share));

        // ∏_{k∈[ℓ]} e(cm_k, g̃^[y_k]_i)
        for (k, commitment) in commitments.iter().enumerate() {
            if k < vk_share.g_tilde_y_shares.len() {
                pairs.push((commitment, &vk_share.g_tilde_y_shares[k]));
            }
        }

        // Verify the pairing equation
        let is_valid_signature = verify_pairing_equation::<E>(&pairs, None);

        Ok(is_valid_signature)
    }

    /// Process signature shares - verify and collect valid ones
    /// Returns collected valid shares
    pub fn process_signature_shares<E: Pairing>(
        commitment_key: &SymmetricCommitmentKey<E>,
        vk_shares: &[VerificationKeyShare<E>],
        commitments: &[E::G1Affine],
        commitment_proofs: &[Vec<u8>],
        signature_shares: &[(usize, PartialSignature<E>)],
        threshold: usize,
    ) -> Result<Vec<(usize, PartialSignature<E>)>, SignatureError> {
        let mut valid_shares = Vec::new();

        for (i, sig_share) in signature_shares {
            // Find the corresponding verification key share
            let vk_share =
                vk_shares
                    .iter()
                    .find(|vk| vk.index == *i)
                    .ok_or(SignatureError::InvalidState(format!(
                        "No verification key for signer {}",
                        i
                    )))?;

            // Verify this signature share
            let is_valid = Self::verify_signature_share(
                commitment_key,
                vk_share,
                commitments,
                commitment_proofs,
                sig_share,
                &mut ark_std::test_rng(),
            )?;

            if is_valid {
                valid_shares.push((*i, sig_share.clone()));
            }
        }

        // Check if we have enough valid shares
        if valid_shares.len() < threshold {
            return Err(SignatureError::from(SignatureError::InsufficientShares {
                needed: threshold + 1,
                got: valid_shares.len(),
            }));
        }

        Ok(valid_shares)
    }
}
