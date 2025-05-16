use crate::errors::SignatureError;
use crate::keygen::{VerificationKey, VerificationKeyShare};
use crate::pairing::{verify_pairing_equation, PairingCheck};
use crate::symmetric_commitment::SymmetricCommitmentKey;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use ark_std::{
    ops::{Add, Mul, Neg},
    One, Zero,
};

#[derive(Clone, Debug)]
pub struct PartialSignature<E: Pairing> {
    pub party_index: usize,
    pub h: E::G1Affine,
    pub sigma: E::G1Affine,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ThresholdSignature<E: Pairing> {
    pub h: E::G1Affine,
    pub sigma: E::G1Affine,
}

impl<E: Pairing> ThresholdSignature<E> {
    /// Verify a signature share from a specific signer
    /// Following RS.ShareVer from the protocol
    pub fn verify_share(
        ck: &SymmetricCommitmentKey<E>,
        vk_share: &VerificationKeyShare<E>,
        commitments: &[E::G1Affine],
        sig_share: &PartialSignature<E>,
    ) -> bool {
        // Verify pairing equation:
        // e(σ_i,2, g̃) = e(h, g̃^[x]_i) · ∏_{k∈[ℓ]} e(cm_k, g̃^[y_k]_i)
        // change to
        // e(-sigma_i, tilde_g) . e(h, g̃^[x]_i) . ∏_{k∈[ℓ]} e(cm_k, g̃^[y_k]_i)

        let mut pairs = Vec::new();

        // e(-sigma_i, g̃) = lhs
        let neg_sigma_i = sig_share.sigma.into_group().neg().into_affine();
        pairs.push((&neg_sigma_i, &ck.g_tilde));

        // Add e(h, g̃^[x]_i)
        let g_tilde_x_share = vk_share.g_tilde_x_share;
        pairs.push((&sig_share.h, &g_tilde_x_share));

        // Add ∏_{k∈[ℓ]} e(cm_k, g̃^[y_k]_i)
        for (k, commitment) in commitments.iter().enumerate() {
            if k < vk_share.g_tilde_y_shares.len() {
                pairs.push((commitment, &vk_share.g_tilde_y_shares[k]));
            }
        }

        // Verify that e(σ_i,2, g̃) = e(h, g̃^[x]_i) · ∏_{k∈[ℓ]} e(cm_k, g̃^[y_k]_i)
        verify_pairing_equation::<E>(&pairs, None)
    }
    /// Aggregate signature shares into a complete threshold signature
    /// A user would do this
    pub fn aggregate_signature_shares(
        ck: &SymmetricCommitmentKey<E>,
        signature_shares: &[(usize, PartialSignature<E>)],
        blindings: &[E::ScalarField],
        threshold: usize,
        h: &E::G1Affine,
    ) -> Result<ThresholdSignature<E>, SignatureError> {
        // Check that we have enough signature shares
        if signature_shares.len() < threshold {
            return Err(SignatureError::InsufficientShares {
                needed: threshold,
                got: signature_shares.len(),
            });
        }

        // Extract indices and signature components
        let mut indices = Vec::with_capacity(signature_shares.len());
        let mut sigma_2_components = Vec::with_capacity(signature_shares.len());

        for (_, share) in signature_shares {
            indices.push(share.party_index);
            sigma_2_components.push((share.party_index, share.sigma));
        }

        // Compute Lagrange coefficients for each party
        let mut sigma_2 = E::G1::zero();

        for (idx, (i, sigma_i_2)) in sigma_2_components.iter().enumerate().take(threshold) {
            // Compute Lagrange coefficient for party i
            let lagrange_i = compute_lagrange_coefficient::<E::ScalarField>(&indices, *i);

            // Add contribution: sigma_i,2^{L_i}
            sigma_2 = sigma_2 + sigma_i_2.mul(lagrange_i);
        }

        // Compute g_k^{r_k}
        let g_k_r_k = E::G1::msm_unchecked(&ck.ck, blindings).neg();
        let final_sigma = (sigma_2 + g_k_r_k).into_affine();

        // Construct the final signature
        Ok(ThresholdSignature {
            h: *h,
            sigma: final_sigma,
        })
    }

    pub fn randomize(&self, rng: &mut impl Rng) -> (ThresholdSignature<E>, E::ScalarField) {
        let u_delta = E::ScalarField::rand(rng);
        let r_delta: <E as Pairing>::ScalarField = E::ScalarField::rand(rng);
        (self.randomize_with_factors(&u_delta, &r_delta), r_delta)
    }

    /// u_delta randomizes sigma1 (h)
    pub fn randomize_with_factors(
        &self,
        u_delta: &E::ScalarField,
        r_delta: &E::ScalarField,
    ) -> ThresholdSignature<E> {
        let h_prime = self.h.mul(u_delta).into_affine();

        // let r_times_u = u_delta.mul(r_delta);
        // let scalars = vec![r_times_u, *u_delta];
        // let points = vec![self.h, self.sigma];
        let temp = self.h.mul(r_delta);
        let sigma_prime = (temp + self.sigma).mul(u_delta).into_affine();

        ThresholdSignature {
            h: h_prime,
            sigma: sigma_prime,
        }
    }

    /// Verify a threshold signature using commitments
    /// Following RS.Ver from the protocol
    pub fn verify(
        ck: &SymmetricCommitmentKey<E>,
        vk: &VerificationKey<E>,
        cm: &E::G1Affine,
        cm_tilde: &E::G2Affine,
        sig: &ThresholdSignature<E>,
        serialized_proof: &[u8],
    ) -> Result<bool, SignatureError> {
        let mut rng = ark_std::test_rng();
        let mr = std::sync::Mutex::new(rng);
        // Optimized check: e(sigma2, g2) * e(sigma1, vk + cmg2)^-1 = 1
        let vk_plus_cm_tilde = vk.g_tilde_x.add(cm_tilde).into_affine();
        let check1 = PairingCheck::<E>::rand(
            &mr,
            &[
                (&sig.sigma, &ck.g_tilde),
                (&sig.h.into_group().neg().into_affine(), &vk_plus_cm_tilde),
            ],
            &E::TargetField::one(),
        );

        // Optimized check: e(cmg1, g2) * e(g1, cmg2)^-1 = 1
        let check2 = PairingCheck::<E>::rand(
            &mr,
            &[
                (cm, &ck.g_tilde),
                (&ck.g.into_group().neg().into_affine(), cm_tilde),
            ],
            &E::TargetField::one(),
        );

        let mut final_check = PairingCheck::<E>::new();
        final_check.merge(&check1);
        final_check.merge(&check2);
        let is_valid = final_check.verify();
        if !is_valid {
            return Err(SignatureError::SignatureVerificationFailed);
        }

        Ok(is_valid)
    }
}

pub fn compute_lagrange_coefficient<F: Field>(indices: &[usize], j: usize) -> F {
    let j_field = F::from(j as u64);

    let mut result = F::one();
    for &i in indices {
        if i == j {
            continue;
        }

        let i_field = F::from(i as u64);
        let numerator = F::zero() - i_field; // Corrected: (0 - x_i) for interpolation at x=0
        let denominator = j_field - i_field; // (x_j - x_i)

        // Compute (0 - x_i)/(x_j - x_i)
        result *= numerator * denominator.inverse().expect("indices should be distinct");
    }
    result
}
