use crate::commitment::CommitmentProof;
use crate::errors::CommitmentError;
use crate::schnorr::SchnorrProtocol;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::ops::{Add, Mul};
use ark_std::rand::Rng;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SymmetricCommitment<E: Pairing> {
    pub ck: SymmetricCommitmentKey<E>,
    pub messages: Vec<E::ScalarField>,
    pub r: E::ScalarField,
    pub cm: E::G1Affine,
    pub cm_tilde: E::G2Affine,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SymmetricCommitmentKey<E: Pairing> {
    pub g: E::G1Affine,
    pub ck: Vec<E::G1Affine>,
    pub g_tilde: E::G2Affine,
    pub ck_tilde: Vec<E::G2Affine>,
}

impl<E: Pairing> SymmetricCommitmentKey<E> {
    /// Create a new symmetric commitment key
    pub fn new(y_values: &[E::ScalarField], rng: &mut impl Rng) -> Self {
        // Generate random base points
        let g = E::G1Affine::rand(rng);
        let g_tilde = E::G2Affine::rand(rng);

        // Compute commitment bases in G1
        let ck = y_values
            .iter()
            .map(|y_k| g.mul(y_k).into_affine())
            .collect();

        // Compute commitment bases in G2
        let ck_tilde = y_values
            .iter()
            .map(|y_k| g_tilde.mul(y_k).into_affine())
            .collect();

        Self {
            g,
            ck,
            g_tilde,
            ck_tilde,
        }
    }

    /// Get all bases for proving
    pub fn get_bases(&self) -> (Vec<E::G1Affine>, Vec<E::G2Affine>) {
        let mut bases = self.ck.clone();
        bases.push(self.g);

        let mut bases_tilde = self.ck_tilde.clone();
        bases_tilde.push(self.g_tilde);

        (bases, bases_tilde)
    }
}

// takes in pp, messages, r. creates cm, cm_tilde by 1. exponentiate each pp.ckg1 with mi and pp.g1 with r, msm together
impl<E: Pairing> SymmetricCommitment<E> {
    pub fn new(
        ck: &SymmetricCommitmentKey<E>,
        messages: &Vec<E::ScalarField>,
        r: &E::ScalarField,
    ) -> Self {
        // Compute commitment in G1
        let cm = g1_commit::<E>(ck, messages, r);

        // Compute commitment in G2
        let cm_tilde = g2_commit::<E>(ck, messages, r);

        Self {
            ck: ck.clone(),
            messages: messages.to_vec(),
            r: *r,
            cm,
            cm_tilde,
        }
    }

    pub fn randomize(&self, r_delta: &E::ScalarField) -> Self {
        let new_r = self.r + r_delta;
        let cm_delta = (self.cm + self.ck.g.mul(r_delta)).into_affine();
        let cm_tilde_delta = (self.cm_tilde + self.ck.g_tilde.mul(r_delta)).into_affine();

        Self {
            ck: self.ck.clone(),
            messages: self.messages.clone(),
            r: new_r,
            cm: cm_delta,
            cm_tilde: cm_tilde_delta,
        }
    }

    pub fn randomize_just_g1(&self, r_delta: &E::ScalarField) -> Self {
        let new_r = self.r + r_delta;
        let cm_delta = (self.cm + self.ck.g.mul(r_delta)).into_affine();

        Self {
            ck: self.ck.clone(),
            messages: self.messages.clone(),
            r: new_r,
            cm: cm_delta,
            cm_tilde: self.cm_tilde,
        }
    }

    // get all exponents of the commitment, C([m_1,...,m_n],r)
    pub fn get_exponents(&self) -> Vec<E::ScalarField> {
        let mut exponents: Vec<E::ScalarField> = self.messages.clone();
        exponents.push(self.r.clone());
        exponents
    }

    pub fn prove(self, rng: &mut impl Rng) -> Result<Vec<u8>, CommitmentError> {
        let bases = self.ck.get_bases().0;
        let schnorr_commitment = SchnorrProtocol::commit(&bases, rng);
        let challenge = E::ScalarField::rand(rng);
        let responses =
            SchnorrProtocol::prove(&schnorr_commitment, &self.get_exponents(), &challenge);
        let proof: CommitmentProof<E> = CommitmentProof {
            commitment: self.cm,
            schnorr_commitment: schnorr_commitment.commited_blindings,
            bases: bases,
            challenge,
            responses: responses.0,
        };

        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;

        Ok(serialized_proof)
    }

    // Verify PoK
    pub fn verify(serialized_proof: &[u8]) -> Result<bool, CommitmentError> {
        let proof: CommitmentProof<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

        // Verify using Schnorr protocol
        let is_valid = SchnorrProtocol::verify_schnorr(
            &proof.bases,
            &proof.commitment,
            &proof.schnorr_commitment,
            &proof.responses,
            &proof.challenge,
        );

        Ok(is_valid)
    }

    // pub fun verify
}

pub fn g1_commit<E: Pairing>(
    ck: &SymmetricCommitmentKey<E>,
    messages: &[E::ScalarField],
    r: &E::ScalarField,
) -> E::G1Affine {
    assert!(messages.len() <= ck.ck.len(), "m.len should be < ck!");
    let g1_r = ck.g.mul(r);
    let ck = &ck.ck[..messages.len()];

    let temp = E::G1::msm_unchecked(ck, messages);
    temp.add(g1_r).into_affine()
}

pub fn g2_commit<E: Pairing>(
    ck: &SymmetricCommitmentKey<E>,
    messages: &[E::ScalarField],
    r: &E::ScalarField,
) -> E::G2Affine {
    assert!(
        messages.len() <= ck.ck_tilde.len(),
        "message.len > ckg2.len"
    );
    // cut ckg2 to the size of m
    let g2_r = ck.g_tilde.mul(r);
    let ck = &ck.ck_tilde[..messages.len()];
    let temp = E::G2::msm_unchecked(ck, messages);
    temp.add(g2_r).into_affine()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir::generate_shares;
    use ark_bls12_381::{Bls12_381, Fr};

    #[test]
    fn test_randomized_commitment() {
        let mut rng = ark_std::test_rng();
        let x = Fr::rand(&mut rng);
        let t = 3;
        let n = 5;
        let l = 4;
        let x_shares = generate_shares(&x, t, n, &mut rng);

        // generate y values [y1,..,yL]
        let mut y_values = Vec::with_capacity(l);
        // [[y1_1,...,y1_L]_1,...,[yL_1,...,yL_L]_k]
        let mut y_shares_by_k = Vec::with_capacity(l);

        // gen l x t degree poly's
        for _ in 0..l {
            let y_k = Fr::rand(&mut rng);
            y_values.push(y_k);
            y_shares_by_k.push(generate_shares(&y_k, t, n, &mut rng));
        }

        let ck: SymmetricCommitmentKey<Bls12_381> =
            SymmetricCommitmentKey::new(&y_values, &mut rng);

        // create commitment with messages
        let messages: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();
        let r = Fr::rand(&mut rng);
        let commitment = SymmetricCommitment::new(&ck, &messages, &r);

        let challenge = Fr::rand(&mut rng);

        // Let's test opening proof
        let (bases, _) = ck.get_bases();
        let schnorr_commitment = SchnorrProtocol::commit(&bases, &mut rng);
        let responses =
            SchnorrProtocol::prove(&schnorr_commitment, &commitment.get_exponents(), &challenge);

        let is_valid = SchnorrProtocol::verify(
            &bases,
            &commitment.cm,
            &schnorr_commitment,
            &responses,
            &challenge,
        );

        assert!(is_valid);
    }
}
