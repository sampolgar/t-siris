use crate::commitment::CommitmentProof;
use crate::errors::CommitmentError;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_serialize::CanonicalDeserialize;
use ark_std::ops::Mul;
use ark_std::rand::Rng;
use ark_std::Zero;

/// Efficient batch verification of multiple Schnorr proofs
/// Returns true only if ALL proofs are valid
pub fn batch_verify<E: Pairing>(
    serialized_proofs: &[Vec<u8>],
    rng: &mut impl Rng,
) -> Result<bool, CommitmentError> {
    if serialized_proofs.is_empty() {
        return Ok(true); // No proofs to verify
    }

    // Step 1: Deserialize all proofs
    let mut deserialized_proofs = Vec::with_capacity(serialized_proofs.len());

    for proof_bytes in serialized_proofs {
        match CommitmentProof::<E>::deserialize_compressed(&proof_bytes[..]) {
            Ok(proof) => deserialized_proofs.push(proof),
            Err(e) => return Err(CommitmentError::SerializationError(e)),
        }
    }

    // Step 2: Perform batch verification using random linear combination
    // Generate a random scalar for each proof
    let random_scalars: Vec<E::ScalarField> = (0..deserialized_proofs.len())
        .map(|_| E::ScalarField::rand(rng))
        .collect();

    // For each proof, compute LHS = g^(r + e*m) and RHS = T * C^e
    let mut all_bases = Vec::new();
    let mut all_scalars = Vec::new();

    // Calculate combined LHS
    for (i, proof) in deserialized_proofs.iter().enumerate() {
        // Add this proof's bases and responses to the combined MSM operation
        // We scale by the random scalar for this proof
        for (base_idx, base) in proof.bases.iter().enumerate() {
            all_bases.push(*base);
            all_scalars.push(proof.responses[base_idx] * random_scalars[i]);
        }
    }

    // Calculate LHS using a single multi-scalar multiplication
    let lhs = E::G1::msm_unchecked(&all_bases, &all_scalars).into_affine();

    // Optimize RHS calculation with a single MSM operation
    let mut rhs_bases = Vec::with_capacity(deserialized_proofs.len() * 2);
    let mut rhs_scalars = Vec::with_capacity(deserialized_proofs.len() * 2);

    for (i, proof) in deserialized_proofs.iter().enumerate() {
        // Add T (schnorr_commitment) with random scalar
        rhs_bases.push(proof.schnorr_commitment);
        rhs_scalars.push(random_scalars[i]);

        // Add C^e (commitment * challenge) with random scalar
        rhs_bases.push(proof.commitment);
        rhs_scalars.push(random_scalars[i] * proof.challenge);
    }

    // Calculate RHS using a single efficient MSM operation
    let rhs = E::G1::msm_unchecked(&rhs_bases, &rhs_scalars).into_affine();

    // Check if LHS == RHS
    Ok(lhs == rhs)
}
/// Efficient batch verification of multiple Schnorr proofs
/// Returns true only if ALL proofs are valid
///
///
///
pub fn batch_verify_old<E: Pairing>(
    serialized_proofs: &[Vec<u8>],
    rng: &mut impl Rng,
) -> Result<bool, CommitmentError> {
    if serialized_proofs.is_empty() {
        return Ok(true); // No proofs to verify
    }

    // Step 1: Deserialize all proofs
    let mut deserialized_proofs = Vec::with_capacity(serialized_proofs.len());

    for proof_bytes in serialized_proofs {
        match CommitmentProof::<E>::deserialize_compressed(&proof_bytes[..]) {
            Ok(proof) => deserialized_proofs.push(proof),
            Err(e) => return Err(CommitmentError::SerializationError(e)),
        }
    }

    // Step 2: Perform batch verification using random linear combination
    // Generate a random scalar for each proof
    let random_scalars: Vec<E::ScalarField> = (0..deserialized_proofs.len())
        .map(|_| E::ScalarField::rand(rng))
        .collect();

    // For each proof, compute LHS = g^(r + e*m) and RHS = T * C^e
    let mut all_bases = Vec::new();
    let mut all_scalars = Vec::new();

    // Calculate combined LHS
    for (i, proof) in deserialized_proofs.iter().enumerate() {
        // Add this proof's bases and responses to the combined MSM operation
        // We scale by the random scalar for this proof
        for (base_idx, base) in proof.bases.iter().enumerate() {
            all_bases.push(*base);
            all_scalars.push(proof.responses[base_idx] * random_scalars[i]);
        }
    }

    // Calculate LHS using a single multi-scalar multiplication
    let lhs = E::G1::msm_unchecked(&all_bases, &all_scalars).into_affine();

    // Calculate combined RHS
    let mut rhs = E::G1::zero();

    for (i, proof) in deserialized_proofs.iter().enumerate() {
        // RHS = T + C^e (scaled by random scalar)
        let rhs_i = proof.schnorr_commitment.into_group()
            + proof.commitment.into_group().mul(proof.challenge);

        // Add to combined RHS with scaling
        rhs = rhs + rhs_i.mul(random_scalars[i]);
    }
    let rhs = rhs.into_affine();

    // Check if LHS == RHS
    Ok(lhs == rhs)
}

// /// Parallel verification of multiple proofs
// /// Each proof is verified independently (not batched)
// pub fn verify_proofs_parallel<E: Pairing>(
//     serialized_proofs: &[Vec<u8>],
// ) -> Result<Vec<bool>, CommitmentError> {
//     #[cfg(feature = "parallel")]
//     {
//         use rayon::prelude::*;

//         let results: Vec<Result<bool, CommitmentError>> = serialized_proofs
//             .par_iter()
//             .map(|proof_bytes| verify::<E>(proof_bytes))
//             .collect();

//         // Process results
//         let mut verification_results = Vec::with_capacity(results.len());
//         for result in results {
//             match result {
//                 Ok(is_valid) => verification_results.push(is_valid),
//                 Err(err) => return Err(err),
//             }
//         }

//         Ok(verification_results)
//     }

//     #[cfg(not(feature = "parallel"))]
//     {
//         let mut verification_results = Vec::with_capacity(serialized_proofs.len());

//         for proof_bytes in serialized_proofs {
//             match verify::<E>(proof_bytes) {
//                 Ok(is_valid) => verification_results.push(is_valid),
//                 Err(err) => return Err(err),
//             }
//         }

//         Ok(verification_results)
//     }
// }
