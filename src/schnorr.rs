// Inspired by Lovesh's work https://github.com/docknetwork/crypto/blob/main/schnorr_pok/src/lib.rs
// TODO let proofs = SchnorrProtocol::new(ck, messages, commitment) this is what it should be!
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::Rng, vec::Vec, UniformRand};

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SchnorrCommitment<G: AffineRepr> {
    pub random_blindings: Vec<G::ScalarField>,
    pub commited_blindings: G,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SchnorrResponses<G: AffineRepr>(pub Vec<G::ScalarField>);

pub struct SchnorrProtocol;

impl SchnorrProtocol {
    /// returns a commitment to random blindings, the commitment T = g_1^{\rho_1},...,g_L^{\rho_L} from random blindings and bases
    pub fn commit<G: AffineRepr, R: Rng>(
        public_generators: &[G],
        rng: &mut R,
    ) -> SchnorrCommitment<G> {
        // random_blindings hide the exponent like a pedersen commitment e.g. g^m h^r
        let random_blindings: Vec<G::ScalarField> = (0..public_generators.len())
            .map(|_| G::ScalarField::rand(rng))
            .collect();
        // Compute t = public_generators[0] * random_blindings[0] + ... + public_generators[i] * random_blindings[i]
        // multi-scalar multiplication - efficient
        let commited_blindings: G =
            G::Group::msm_unchecked(public_generators, &random_blindings).into_affine();
        SchnorrCommitment {
            random_blindings,
            commited_blindings,
        }
    }

    /// returns a commitment to random blindings, the commitment T = g_1^{\rho_1},...,g_L^{\rho_L} from random blindings and bases
    pub fn commit_with_prepared_blindings<G: AffineRepr>(
        public_generators: &[G],
        random_blindings: &[G::ScalarField],
    ) -> SchnorrCommitment<G> {
        let commited_blindings: G =
            G::Group::msm_unchecked(public_generators, &random_blindings).into_affine();
        SchnorrCommitment {
            random_blindings: random_blindings.to_vec(),
            commited_blindings,
        }
    }

    // commit takes in public_generators and exponents
    pub fn commit_equality<G: AffineRepr, R: Rng>(
        public_generators: &[G],
        rng: &mut R,
        equal_blindness: &G::ScalarField,
        index: usize, //hard code index to 0
    ) -> SchnorrCommitment<G> {
        // random_blindings hide the exponent like a pedersen commitment e.g. g^m h^r

        let mut random_blindings: Vec<G::ScalarField> = (1..public_generators.len())
            .map(|_| G::ScalarField::rand(rng))
            .collect();

        // Insert equal_blindness at the front of the vector
        random_blindings.insert(0, *equal_blindness);
        // Compute t = public_generators[0] * random_blindings[0] + ... + public_generators[i] * random_blindings[i]
        // multi-scalar multiplication - efficient
        let commited_blindings: G =
            G::Group::msm_unchecked(public_generators, &random_blindings).into_affine();
        SchnorrCommitment {
            random_blindings,
            commited_blindings,
        }
    }

    pub fn prove<G: AffineRepr>(
        commitment: &SchnorrCommitment<G>, //schnorr commitment
        witnesses: &[G::ScalarField],
        challenge: &G::ScalarField,
    ) -> SchnorrResponses<G> {
        // z_i = t_i + e * m_i
        let schnorr_responsess: Vec<G::ScalarField> = commitment
            .random_blindings
            .iter()
            .zip(witnesses.iter())
            .map(|(b, w)| *b + (*w * challenge))
            .collect();
        SchnorrResponses(schnorr_responsess)
    }

    // this shouldn't be used, taking in SchnorrResponses is silly because it has randomness
    pub fn verify<G: AffineRepr>(
        public_generators: &[G],
        statement: &G,
        blinding_commitment: &SchnorrCommitment<G>,
        schnorr_responses: &SchnorrResponses<G>,
        challenge: &G::ScalarField,
    ) -> bool {
        //e.g.  LHS = g1^(t1 + e*m1) * g2^(t2 + e*m2) * h^(t3 + e*r)
        let lhs = G::Group::msm_unchecked(public_generators, &schnorr_responses.0).into_affine();
        // com^e + com
        let rhs =
            (blinding_commitment.commited_blindings + statement.mul(*challenge)).into_affine();
        lhs == rhs
    }

    /// takes input Generators, Statement, Schnorr Commitment \in G, Schnorr responses, challenge
    pub fn verify_schnorr<G: AffineRepr>(
        public_generators: &[G],
        statement: &G,
        schnorr_commitment: &G,
        schnorr_responses: &[G::ScalarField],
        challenge: &G::ScalarField,
    ) -> bool {
        //e.g.  LHS = g1^(t1 + e*m1) * g2^(t2 + e*m2) * h^(t3 + e*r)
        let lhs = G::Group::msm_unchecked(public_generators, &schnorr_responses).into_affine();
        // com^e + com
        let rhs = (schnorr_commitment.into_group() + statement.mul(*challenge)).into_affine();
        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine};
    use ark_std::test_rng;
    // use blake2::Blake2b512;

    #[test]
    fn test_schnorr_single() {
        let mut rng = test_rng();

        fn check<G: AffineRepr>(rng: &mut impl Rng) {
            let base = G::Group::rand(rng).into_affine();
            let witness = G::ScalarField::rand(rng);
            let statement = base.mul(witness).into_affine();

            let schnorr_commitment = SchnorrProtocol::commit(&[base], rng);

            let challenge = G::ScalarField::rand(rng);

            let schnorr_responses =
                SchnorrProtocol::prove(&schnorr_commitment, &[witness], &challenge);

            assert!(SchnorrProtocol::verify(
                &[base],
                &statement,
                &schnorr_commitment,
                &schnorr_responses,
                &challenge
            ));
        }

        check::<G1Affine>(&mut rng);
        check::<G2Affine>(&mut rng);
    }

    #[test]
    fn test_schnorr_double() {
        let mut rng = test_rng();

        fn check<G: AffineRepr>(rng: &mut impl Rng) {
            let base1 = G::Group::rand(rng).into_affine();
            let witness1 = G::ScalarField::rand(rng);
            let base2 = G::Group::rand(rng).into_affine();
            let witness2 = G::ScalarField::rand(rng);
            let public_statement = (base1.mul(witness1) + base2.mul(witness2)).into_affine();

            let commitment = SchnorrProtocol::commit(&[base1, base2], rng);
            let challenge = G::ScalarField::rand(rng);

            let schnorr_responses =
                SchnorrProtocol::prove(&commitment, &[witness1, witness2], &challenge);

            assert!(SchnorrProtocol::verify(
                &[base1, base2],
                &public_statement,
                &commitment,
                &schnorr_responses,
                &challenge
            ));
        }

        check::<G1Affine>(&mut rng);
        check::<G2Affine>(&mut rng);
    }

    #[test]
    fn test_schnorr_tripple() {
        let mut rng = test_rng();

        // Generate public_generators and witnesses
        let num_witnesses = 3;
        let public_generators: Vec<G1Affine> = (0..num_witnesses)
            .map(|_| G1Affine::rand(&mut rng))
            .collect();
        let witnesses: Vec<Fr> = (0..num_witnesses).map(|_| Fr::rand(&mut rng)).collect();

        // Compute Commitment
        let public_statement =
            G1Projective::msm_unchecked(&public_generators, &witnesses).into_affine();

        // Prover's side
        let commitment = SchnorrProtocol::commit(&public_generators, &mut rng);
        let challenge = Fr::rand(&mut rng); // In practice, this should be derived from a hash
        let schnorr_responses = SchnorrProtocol::prove(&commitment, &witnesses, &challenge);

        // Verifier's side
        let is_valid = SchnorrProtocol::verify(
            &public_generators,
            &public_statement,
            &commitment,
            &schnorr_responses,
            &challenge,
        );

        assert!(is_valid, "Schnorr proof verification failed");
    }
}
