use crate::shamir::generate_shares;
use crate::symmetric_commitment::SymmetricCommitmentKey;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_std::ops::Mul;
use ark_std::rand::Rng;

#[derive(Clone)]
pub struct SecretKeyShare<E: Pairing> {
    pub index: usize,
    pub x_share: E::ScalarField,
    pub y_shares: Vec<E::ScalarField>,
}
#[derive(Clone)]
pub struct ThresholdKeys<E: Pairing> {
    pub t: usize,
    pub n: usize,
    pub l: usize,
    pub sk_shares: Vec<SecretKeyShare<E>>,
    pub vk_shares: Vec<VerificationKeyShare<E>>,
}

#[derive(Clone)]
pub struct VerificationKey<E: Pairing> {
    pub g_tilde_x: E::G2Affine,
}

#[derive(Clone)]
pub struct VerificationKeyShare<E: Pairing> {
    pub index: usize,
    pub g_tilde_x_share: E::G2Affine,
    pub g_tilde_y_shares: Vec<E::G2Affine>,
}

pub fn keygen<E: Pairing>(
    t: usize,
    n: usize,
    l: usize,
    rng: &mut impl Rng,
) -> (
    SymmetricCommitmentKey<E>,
    VerificationKey<E>,
    ThresholdKeys<E>,
) {
    // 1. generate x and xshares
    let x = E::ScalarField::rand(rng);
    let x_shares = generate_shares(&x, t, n, rng);

    // generate y values [y1,..,yL]
    let mut y_values = Vec::with_capacity(l);
    // [[y1_1,...,y1_L]_1,...,[yL_1,...,yL_L]_k]
    let mut y_shares_by_k = Vec::with_capacity(l);

    // gen l x t degree poly's
    for _ in 0..l {
        let y_k = E::ScalarField::rand(rng);
        y_values.push(y_k);
        y_shares_by_k.push(generate_shares(&y_k, t, n, rng));
    }

    let ck: SymmetricCommitmentKey<E> = SymmetricCommitmentKey::new(&y_values, rng);

    let g_tilde_x = ck.g_tilde.mul(x).into_affine();
    let vk: VerificationKey<E> = VerificationKey { g_tilde_x };

    // exponentiate the shares for g1,g2 values of shares
    let mut sk_shares = Vec::with_capacity(n);
    let mut vk_shares = Vec::with_capacity(n);

    for i in 0..n {
        // looping from (1, x_1),...,(L, x_L)

        let (idx, x_share_i) = x_shares[i];

        let mut y_shares_i = Vec::with_capacity(l);
        let mut g_tilde_y_shares_i = Vec::with_capacity(l);

        // from [[y1_1,...,y1_L]_1,...,[yL_1,...,YL_L]_k]
        // select from each y_L array for size [k] [y1_1,...,yL_1]_[k]
        for k in 0..l {
            let (_, y_share_k_i) = y_shares_by_k[k][i];
            y_shares_i.push(y_share_k_i);
            g_tilde_y_shares_i.push(ck.g_tilde.mul(y_share_k_i).into_affine());
        }

        let sk_share = SecretKeyShare {
            index: idx,
            x_share: x_share_i,
            y_shares: y_shares_i,
        };

        let vk_share = VerificationKeyShare {
            index: idx,
            g_tilde_x_share: ck.g_tilde.mul(x_share_i).into_affine(),
            g_tilde_y_shares: g_tilde_y_shares_i,
        };

        sk_shares.push(sk_share);
        vk_shares.push(vk_share);
    }

    let ts_keys = ThresholdKeys {
        t,
        n,
        l,
        sk_shares,
        vk_shares,
    };

    (ck, vk, ts_keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir::reconstruct_secret;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ec::pairing::Pairing;
    use ark_ec::CurveGroup;
    use ark_std::test_rng;

    #[test]
    fn test_dist_keygen() {
        let mut rng = test_rng();
        let threshold = 2; // t=2, need t+1=3 participants to reconstruct
        let n_participants = 5;
        let l_attributes = 3;

        // Generate threshold keys
        // Destructuring with type annotation
        let (ck, vk, ts_keys): (
            SymmetricCommitmentKey<Bls12_381>,
            VerificationKey<Bls12_381>,
            ThresholdKeys<Bls12_381>,
        ) = keygen(threshold, n_participants, l_attributes, &mut rng);

        // Verify number of participants
        assert_eq!(ts_keys.sk_shares.len(), n_participants);
        assert_eq!(ts_keys.vk_shares.len(), n_participants);

        // Verify each participant has correct number of y shares
        for i in 0..n_participants {
            assert_eq!(ts_keys.sk_shares[i].y_shares.len(), l_attributes);
            assert_eq!(ts_keys.vk_shares[i].g_tilde_y_shares.len(), l_attributes);
        }

        // Test reconstruction with t+1 participants
        let subset_indices = (0..threshold + 1).collect::<Vec<_>>();

        // Collect x shares from these participants
        let x_shares_subset: Vec<(usize, Fr)> = subset_indices
            .iter()
            .map(|&i| (ts_keys.sk_shares[i].index, ts_keys.sk_shares[i].x_share))
            .collect();

        // Reconstruct x
        let reconstructed_x: <Bls12_381 as Pairing>::ScalarField =
            reconstruct_secret(&x_shares_subset, threshold + 1);

        let computed_g_tilde_x = ck.g_tilde.mul(reconstructed_x).into_affine();
        assert_eq!(
            computed_g_tilde_x, vk.g_tilde_x,
            "Reconstructed x verification failed"
        );

        // Test reconstruction of each y_k
        for k in 0..l_attributes {
            let y_k_shares_subset: Vec<(usize, Fr)> = subset_indices
                .iter()
                .map(|&i| (ts_keys.sk_shares[i].index, ts_keys.sk_shares[i].y_shares[k]))
                .collect();

            let reconstructed_y_k: Fr = reconstruct_secret(&y_k_shares_subset, threshold + 1);
            let computed_g_tilde_y_k = ck.g_tilde.mul(reconstructed_y_k).into_affine();
            assert_eq!(
                computed_g_tilde_y_k, ck.ck_tilde[k],
                "Reconstructed y_{} verification failed",
                k
            );
        }
    }
}
