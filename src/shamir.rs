use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_std::{rand::Rng, vec::Vec};
use std::ops::Mul;

/// Generates shares for a secret using Shamir's Secret Sharing scheme
pub fn generate_shares<F: Field, R: Rng>(
    secret: &F,
    threshold: usize,
    num_shares: usize,
    rng: &mut R,
) -> Vec<(usize, F)> {
    // Ensure parameters are valid
    assert!(threshold > 0, "Threshold must be positive");
    assert!(
        num_shares >= threshold,
        "Number of shares must be at least the threshold"
    );

    let mut coefficients = Vec::with_capacity(threshold);
    coefficients.push(*secret); // a_0 = secret

    // Generate random coefficients a_1, a_2, ..., a_{t-1}
    for _ in 1..threshold {
        coefficients.push(F::rand(rng));
    }

    // Evaluate the polynomial at points 1, 2, ..., n
    let mut shares = Vec::with_capacity(num_shares);
    for i in 1..=num_shares {
        // Convert i to field element
        let x = F::from(i as u64);

        // Evaluate polynomial at x using Horner's method
        let mut y = coefficients[threshold - 1];
        for j in (0..threshold - 1).rev() {
            y = y * x + coefficients[j];
        }

        shares.push((i, y));
    }

    shares
}

/// Reconstructs a secret from t shares using Lagrange interpolation
pub fn reconstruct_secret<F: Field>(shares: &[(usize, F)], threshold: usize) -> F {
    assert!(
        shares.len() >= threshold,
        "Not enough shares for reconstruction"
    );

    let shares = &shares[0..threshold]; // Only use t shares

    // Compute the secret (f(0)) using Lagrange interpolation
    let mut secret = F::zero();

    for (i, (x_i, y_i)) in shares.iter().enumerate() {
        let mut lagrange_coef = F::one();

        // Calculate the Lagrange basis polynomial evaluated at 0
        for (j, (x_j, _)) in shares.iter().enumerate() {
            if i != j {
                // (0 - x_j) / (x_i - x_j)
                let numerator = F::zero() - F::from(*x_j as u64);
                let denominator = F::from(*x_i as u64) - F::from(*x_j as u64);
                // Multiply by the inverse since we're in a field
                lagrange_coef = lagrange_coef * numerator * denominator.inverse().unwrap();
            }
        }

        // Multiply by y_i and add to result
        secret = secret + (*y_i * lagrange_coef);
    }

    secret
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::One;
    use ark_std::test_rng;

    #[test]
    fn test_shamir_secret_sharing_basic() {
        let mut rng = test_rng();

        let secret = Fr::rand(&mut rng);
        let threshold = 3;
        let num_shares = 5;

        let shares = generate_shares(&secret, threshold, num_shares, &mut rng);

        assert_eq!(shares.len(), num_shares);

        let reconstructed_secret = reconstruct_secret(&shares[0..threshold], threshold);
        assert_eq!(reconstructed_secret, secret);
    }
}
