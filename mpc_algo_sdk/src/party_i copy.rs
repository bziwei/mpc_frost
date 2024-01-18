use crate::prelude::*;

use curve25519_dalek::{constants, ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};
use rand::{CryptoRng, RngCore};
use std::collections::HashMap;
use std::convert::TryInto;
use zeroize::Zeroize;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharesCommitment {
    pub commitment: Vec<RistrettoPoint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenDKGProposedCommitment {
    pub index: u16,
    pub shares_commitment: SharesCommitment,
    pub zkp: KeyGenZKP,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenDKGCommitment {
    pub index: u16,
    pub shares_commitment: SharesCommitment,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Share {
    generator_index: u16,
    pub receiver_index: u16,
    value: Scalar,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct KeyInitial {
    pub index: u16,
    pub u_i: Scalar,
    pub k: Scalar,
    pub g_u_i: RistrettoPoint,
    pub g_k: RistrettoPoint,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct KeyPair {
    pub index: u16,
    pub x_i: Scalar,
    pub g_x_i: RistrettoPoint,
    pub group_public: RistrettoPoint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningResponse {
    pub response: Scalar,
    pub index: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningCommitmentPair {
    pub index: u16,
    g_d: RistrettoPoint,
    g_e: RistrettoPoint,
}

#[derive(Copy, Clone)]
pub struct SigningNoncePair {
    d: Nonce,
    e: Nonce,
}

#[derive(Copy, Clone)]
pub struct Nonce {
    secret: Scalar,
    pub public: RistrettoPoint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenZKP {
    pub g_k: RistrettoPoint, // KeyGen: g_k
    pub sigma: Scalar,       // KeyGen: sigma
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub R: RistrettoPoint, // Sign: R
    pub z: Scalar,         // Sign: z
    pub hash: Vec<u8>,     // Sign: hashed message
}

impl Zeroize for KeyGenDKGProposedCommitment {
    fn zeroize(&mut self) {
        self.index.zeroize();
        self.shares_commitment.zeroize();
        self.zkp.zeroize();
    }
}

impl Zeroize for SharesCommitment {
    fn zeroize(&mut self) {
        self.commitment.iter_mut().for_each(Zeroize::zeroize);
    }
}

impl Zeroize for KeyGenZKP {
    fn zeroize(&mut self) {
        self.g_k.zeroize();
        self.sigma.zeroize();
    }
}

impl Zeroize for Share {
    fn zeroize(&mut self) {
        self.generator_index.zeroize();
        self.receiver_index.zeroize();
        self.value.zeroize();
    }
}

impl KeyGenDKGProposedCommitment {
    pub fn is_valid_zkp(&self, challenge: Scalar) -> Outcome<()> {
        assert_throw!(
            self.zkp.g_k
                == (&constants::RISTRETTO_BASEPOINT_TABLE * &self.zkp.sigma)
                    - (self.get_commitment_to_secret() * challenge)
        );

        Ok(())
    }

    pub fn get_commitment_to_secret(&self) -> RistrettoPoint {
        self.shares_commitment.commitment[0]
    }
}

impl Share {
    pub fn new_from(generator_index: u16, receiver_index: u16, value: Scalar) -> Self {
        Self {
            generator_index,
            receiver_index,
            value,
        }
    }

    pub fn get_value(&self) -> Scalar {
        self.value
    }

    /// Verify that a share is consistent with a commitment.
    fn verify_share(&self, com: &SharesCommitment) -> Outcome<()> {
        let f_result = &constants::RISTRETTO_BASEPOINT_TABLE * &self.value;

        let term = Scalar::from(self.receiver_index);
        let mut result = RistrettoPoint::identity();

        // Thanks to isis lovecruft for their simplification to Horner's method;
        // including it here for readability. Their implementation of FROST can
        // be found here: github.com/isislovecruft/frost-dalek
        for (index, comm_i) in com.commitment.iter().rev().enumerate() {
            result += comm_i;

            if index != com.commitment.len() - 1 {
                result *= term;
            }
        }
        assert_throw!(f_result == result);

        Ok(())
    }
}

impl KeyInitial {
    pub fn new<R: RngCore + CryptoRng>(index: u16, rng: &mut R) -> Self {
        let u_i = Scalar::random(rng);
        let k = Scalar::random(rng);
        let g_u_i = &constants::RISTRETTO_BASEPOINT_TABLE * &u_i;
        let g_k = &constants::RISTRETTO_BASEPOINT_TABLE * &k;
        Self {
            index,
            u_i,
            k,
            g_u_i,
            g_k,
        }
    }

    pub fn create_from<R: RngCore + CryptoRng>(u_i: Scalar, index: u16, rng: &mut R) -> Self {
        let k = Scalar::random(rng);
        let g_u_i = &constants::RISTRETTO_BASEPOINT_TABLE * &u_i;
        let g_k = &constants::RISTRETTO_BASEPOINT_TABLE * &k;
        Self {
            index,
            u_i,
            k,
            g_u_i,
            g_k,
        }
    }

    /// Create secret shares for a given secret. This function accepts a secret to
    /// generate shares from. While in FROST this secret should always be generated
    /// randomly, we allow this secret to be specified for this internal function
    /// for testability
    pub fn generate_shares<R: RngCore + CryptoRng>(
        &self,
        n_shares: u16,
        quorum: u16,
        rng: &mut R,
    ) -> Outcome<(SharesCommitment, Vec<Share>)> {
        assert_throw!(quorum >= 1);
        assert_throw!(n_shares >= quorum);

        let numcoeffs = quorum;
        let mut coefficients = (0..numcoeffs)
            .map(|_| Scalar::random(rng))
            .collect::<Vec<_>>();

        let commitment = coefficients.iter().fold(vec![self.g_u_i], |mut acc, c| {
            acc.push(&constants::RISTRETTO_BASEPOINT_TABLE * &c);
            acc
        });

        let shares = (1..=n_shares)
            .map(|index| {
                // Evaluate the polynomial with `secret` as the constant term
                // and `coeffs` as the other coefficients at the point x=share_index
                // using Horner's method
                let scalar_index = Scalar::from(index);
                let mut value = Scalar::zero();
                for i in (0..numcoeffs).rev() {
                    value += &coefficients[i as usize];
                    value *= scalar_index;
                }
                // The secret is the *constant* term in the polynomial used for
                // secret sharing, this is typical in schemes that build upon Shamir
                // Secret Sharing.
                value += self.u_i;
                Share {
                    generator_index: self.index,
                    receiver_index: index,
                    value,
                }
            })
            .collect::<Vec<_>>();
        coefficients.iter_mut().for_each(|c| c.zeroize());
        Ok((SharesCommitment { commitment }, shares))
    }

    /// keygen_receive_commitments_and_validate_peers gathers commitments from
    /// peers and validates the zero knowledge proof of knowledge for the peer's
    /// secret term. It returns a list of all participants who failed the check,
    /// a list of commitments for the peers that remain in a valid state,
    /// and an error term.
    ///
    /// Here, we return a DKG commitmentment that is explicitly marked as valid,
    /// to ensure that this step of the protocol is performed before going on to
    /// keygen_finalize
    pub fn keygen_receive_commitments_and_validate_peers(
        peer_commitments: Vec<KeyGenDKGProposedCommitment>,
        context: &str,
    ) -> Outcome<(Vec<u16>, Vec<KeyGenDKGCommitment>)> {
        let mut invalid_peer_ids = Vec::new();
        let mut valid_peer_commitments: Vec<KeyGenDKGCommitment> =
            Vec::with_capacity(peer_commitments.len());

        for commitment in peer_commitments {
            let challenge = generate_dkg_challenge(
                commitment.index,
                context,
                commitment.get_commitment_to_secret(),
                commitment.zkp.g_k,
            )
            .catch_()?;

            if !commitment.is_valid_zkp(challenge).is_ok() {
                invalid_peer_ids.push(commitment.index);
            } else {
                valid_peer_commitments.push(KeyGenDKGCommitment {
                    index: commitment.index,
                    shares_commitment: commitment.shares_commitment,
                });
            }
        }

        Ok((invalid_peer_ids, valid_peer_commitments))
    }

    pub fn keygen_verify_share_construct_keypair(
        party_shares: Vec<Share>,
        shares_com_vec: Vec<KeyGenDKGCommitment>,
        index: u16,
    ) -> Outcome<KeyPair> {
        // first, verify the integrity of the shares
        for share in &party_shares {
            let commitment = shares_com_vec
                .iter()
                .find(|comm| comm.index == share.generator_index)
                .ifnone_()?;
            share.verify_share(&commitment.shares_commitment)?;
        }

        let x_i = party_shares
            .iter()
            .fold(Scalar::zero(), |acc, x| acc + x.value);
        let g_x_i = &constants::RISTRETTO_BASEPOINT_TABLE * &x_i;

        let group_public = shares_com_vec
            .iter()
            .map(|c| c.shares_commitment.commitment[0])
            .fold(RistrettoPoint::identity(), |acc, x| acc + x);

        Ok(KeyPair {
            index,
            x_i,
            g_x_i,
            group_public,
        })
    }
}

impl KeyPair {
    /// preprocess is performed by each participant; their commitments are published
    /// and stored in an external location for later use in signing, while their
    /// signing nonces are stored locally.
    pub fn sign_preprocess<R: RngCore + CryptoRng>(
        cached_com_count: usize,
        participant_index: u16,
        rng: &mut R,
    ) -> Outcome<(Vec<SigningCommitmentPair>, Vec<SigningNoncePair>)> {
        let (commitments, nonces): (Vec<_>, Vec<_>) = (0..cached_com_count)
            .map(|_| {
                let nonce_pair = SigningNoncePair::new(rng).catch_()?;
                let commitment = SigningCommitmentPair::new(
                    participant_index,
                    nonce_pair.d.public,
                    nonce_pair.e.public,
                )
                .catch_()?;
                Ok((commitment, nonce_pair))
            })
            .collect::<Outcome<Vec<_>>>()?
            .into_iter()
            .unzip();

        Ok((commitments, nonces))
    }

    /// sign is performed by each participant selected for the signing
    /// operation; these responses are then aggregated into the final FROST
    /// signature by the signature aggregator performing the aggregate function
    /// with each response.
    pub fn sign_and_respond(
        &self,
        signing_commitments: &Vec<SigningCommitmentPair>, // B, but how to construct B???
        signing_nonces: &mut Vec<SigningNoncePair>,
        msg: &[u8],
    ) -> Outcome<SigningResponse> {
        // no message checking???
        // no D_l and E_l checking???

        let mut bindings: HashMap<u16, Scalar> = HashMap::with_capacity(signing_commitments.len());

        for comm in signing_commitments {
            let rho_i = gen_rho_i(comm.index, msg, signing_commitments); // rho_l = H_1(l, m, B)
            let _ = bindings.insert(comm.index, rho_i); // (l, rho_l)
        }

        // R = k * G = sum(D_l + E_l * rho_l)
        let group_commitment = gen_group_commitment(&signing_commitments, &bindings).catch_()?;

        let indices = signing_commitments
            .iter()
            .map(|item| item.index)
            .collect::<Vec<_>>();

        let lambda_i = get_lagrange_coeff(0, self.index, &indices).catch_()?;

        // find the corresponding nonces for this participant
        let my_comm = signing_commitments
            .iter()
            .find(|item| item.index == self.index)
            .ifnone("", "No signing commitment for signer")?;

        let signing_nonce_position = signing_nonces
            .iter_mut()
            .position(|item| item.d.public == my_comm.g_d && item.e.public == my_comm.g_e)
            .ifnone("", "No matching signing nonce for signer")?;

        // retrieve d_i, e_i
        let signing_nonce = signing_nonces
            .get(signing_nonce_position)
            .ifnone("", "cannot retrieve nonce from position~")?;

        let my_rho_i = bindings[&self.index]; // [party_id]

        // c= H_2(R, Y, m)
        let c = generate_challenge(msg, group_commitment);

        // z_i = d_i + (e_i * rho_i) + lambda_i * s_i * c
        let response = signing_nonce.d.secret
            + (signing_nonce.e.secret * my_rho_i)
            + (lambda_i * self.x_i * c);

        // Now that this nonce has been used, delete it
        let _ = signing_nonces.remove(signing_nonce_position);

        Ok(SigningResponse {
            response,          // z_i
            index: self.index, // party id
        })
    }

    /// aggregate collects all responses from participants. It first performs a
    /// validity check for each participant's response, and will return an error in the
    /// case the response is invalid. If all responses are valid, it aggregates these
    /// into a single signature that is published. This function is executed
    /// by the entity performing the signature aggregator role.
    pub fn sign_aggregate_responses(
        msg: &[u8],
        signing_commitments: &Vec<SigningCommitmentPair>,
        signing_responses: &Vec<SigningResponse>,
        signer_pubkeys: &HashMap<u16, RistrettoPoint>,
    ) -> Outcome<Signature> {
        assert_throw!(signing_commitments.len() == signing_responses.len());

        // first, make sure that each commitment corresponds to exactly one response
        let mut commitment_indices = signing_commitments
            .iter()
            .map(|com| com.index)
            .collect::<Vec<u16>>();
        let mut response_indices = signing_responses
            .iter()
            .map(|com| com.index)
            .collect::<Vec<u16>>();

        commitment_indices.sort();
        response_indices.sort();
        assert_throw!(commitment_indices == response_indices);

        let mut bindings: HashMap<u16, Scalar> = HashMap::with_capacity(signing_commitments.len());

        for counter in 0..signing_commitments.len() {
            let comm = &signing_commitments[counter];
            let rho_i = gen_rho_i(comm.index, msg, signing_commitments);
            let _ = bindings.insert(comm.index, rho_i);
        }

        let group_commitment = gen_group_commitment(&signing_commitments, &bindings).catch_()?;
        let challenge = generate_challenge(msg, group_commitment);

        // check the validity of each participant's response
        for resp in signing_responses {
            let matching_rho_i = bindings[&resp.index];

            let indices = signing_commitments
                .iter()
                .map(|item| item.index)
                .collect::<Vec<_>>();

            let lambda_i = get_lagrange_coeff(0, resp.index, &indices).catch_()?;

            let matching_commitment = signing_commitments
                .iter()
                .find(|x| x.index == resp.index)
                .ifnone("", "No matching commitment for response")?;

            let commitment_i = matching_commitment.g_d + (matching_commitment.g_e * matching_rho_i);
            let signer_pubkey = signer_pubkeys
                .get(&matching_commitment.index)
                .ifnone("", "commitment does not have a matching signer public key!")?;

            let resp_is_valid = resp.is_valid(&signer_pubkey, lambda_i, &commitment_i, challenge);
            assert_throw!(resp_is_valid);
        }

        let group_resp = signing_responses
            .iter()
            .fold(Scalar::zero(), |acc, x| acc + x.response);

        Ok(Signature {
            R: group_commitment,
            z: group_resp,
            hash: msg.to_vec(),
        })
    }
}

impl SigningResponse {
    pub fn is_valid(
        &self,
        pubkey: &RistrettoPoint,
        lambda_i: Scalar,
        commitment: &RistrettoPoint,
        challenge: Scalar,
    ) -> bool {
        (&constants::RISTRETTO_BASEPOINT_TABLE * &self.response)
            == (commitment + (pubkey * (challenge * lambda_i)))
    }
}

impl SigningCommitmentPair {
    pub fn new(
        index: u16,
        g_d: RistrettoPoint,
        g_e: RistrettoPoint,
    ) -> Outcome<SigningCommitmentPair> {
        assert_throw!(g_d != RistrettoPoint::identity() && g_e != RistrettoPoint::identity());

        Ok(SigningCommitmentPair { g_d, g_e, index })
    }
}

impl SigningNoncePair {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Outcome<SigningNoncePair> {
        let (d, e) = (Scalar::random(rng), Scalar::random(rng));
        let (d_pub, e_pub) = (
            &constants::RISTRETTO_BASEPOINT_TABLE * &d,
            &constants::RISTRETTO_BASEPOINT_TABLE * &e,
        );

        assert_throw!(d_pub != RistrettoPoint::identity() && e_pub != RistrettoPoint::identity());

        Ok(SigningNoncePair {
            d: Nonce {
                secret: d,
                public: d_pub,
            },
            e: Nonce {
                secret: e,
                public: e_pub,
            },
        })
    }
}

pub fn generate_dkg_challenge(
    index: u16,
    context: &str,
    public: RistrettoPoint,
    commitment: RistrettoPoint,
) -> Outcome<Scalar> {
    let mut hasher = Sha256::new();
    // the order of the below may change to allow for EdDSA verification compatibility
    hasher.update(commitment.compress().to_bytes());
    hasher.update(public.compress().to_bytes());
    hasher.update(index.to_string());
    hasher.update(context);
    let result = hasher.finalize();

    let a: [u8; 32] = result.as_slice().try_into().catch_()?;

    Ok(Scalar::from_bytes_mod_order(a))
}

/// generates the lagrange coefficient for the ith participant. This allows
/// for performing Lagrange interpolation, which underpins threshold secret
/// sharing schemes based on Shamir secret sharing.
pub fn get_lagrange_coeff(
    x_coord: u16,
    signer_index: u16,
    all_signer_indices: &[u16],
) -> Outcome<Scalar> {
    let mut num = Scalar::one();
    let mut den = Scalar::one();
    for j in all_signer_indices {
        if *j == signer_index {
            continue;
        }
        num *= Scalar::from(*j) - Scalar::from(x_coord);
        den *= Scalar::from(*j) - Scalar::from(signer_index);
    }

    assert_throw!(den != Scalar::zero(), "Duplicate shares provided");

    let lagrange_coeff = num * den.invert();

    Ok(lagrange_coeff)
}

// get g_x_i locally
pub fn get_ith_pubkey(index: u16, commitments: &Vec<KeyGenDKGCommitment>) -> RistrettoPoint {
    let mut ith_pubkey = RistrettoPoint::identity();
    let term = Scalar::from(index);

    // iterate over each commitment
    for commitment in commitments {
        let mut result = RistrettoPoint::identity();
        let t = commitment.shares_commitment.commitment.len() as u16;
        // iterate  over each element in the commitment
        for (inner_index, comm_i) in commitment
            .shares_commitment
            .commitment
            .iter()
            .rev()
            .enumerate()
        {
            result += comm_i;

            // handle constant term
            if inner_index as u16 != t - 1 {
                result *= term;
            }
        }

        ith_pubkey += result;
    }

    ith_pubkey
}

/// validate performs a plain Schnorr validation operation; this is identical
/// to performing validation of a Schnorr signature that has been signed by a
/// single party.
pub fn validate(
    // msg: &str,
    sig: &Signature,
    pubkey: &RistrettoPoint
) -> Outcome<()> {
    let challenge = generate_challenge(&sig.hash, sig.R);
    assert_throw!(
        sig.R == (&constants::RISTRETTO_BASEPOINT_TABLE * &sig.z) - (pubkey * challenge),
        "Invalid signature"
    );

    Ok(())
}

// to be reviewed again? For H(m, R) instead of H(R, Y, m)???
/// generates the challenge value H(m, R) used for both signing and verification.
/// ed25519_ph hashes the message first, and derives the challenge as H(H(m), R),
/// this would be a better optimization but incompatibility with other
/// implementations may be undesirable.
pub fn generate_challenge(msg: &[u8], group_commitment: RistrettoPoint) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(group_commitment.compress().to_bytes());
    hasher.update(msg);
    let result = hasher.finalize();

    let x = result
        .as_slice()
        .try_into()
        .expect("Error generating commitment!");
    Scalar::from_bytes_mod_order(x)
}

fn gen_rho_i(index: u16, msg: &[u8], signing_commitments: &Vec<SigningCommitmentPair>) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update("I".as_bytes());
    hasher.update(index.to_be_bytes());
    hasher.update(msg);
    for item in signing_commitments {
        hasher.update(item.index.to_be_bytes());
        hasher.update(item.g_d.compress().as_bytes());
        hasher.update(item.g_e.compress().as_bytes());
    }
    let result = hasher.finalize();

    let x = result
        .as_slice()
        .try_into()
        .expect("Error generating commitment!");
    Scalar::from_bytes_mod_order(x)
}

fn gen_group_commitment(
    signing_commitments: &Vec<SigningCommitmentPair>,
    bindings: &HashMap<u16, Scalar>,
) -> Outcome<RistrettoPoint> {
    let mut accumulator = RistrettoPoint::identity();

    for commitment in signing_commitments {
        let rho_i = bindings[&commitment.index];

        accumulator += commitment.g_d + (commitment.g_e * rho_i)
    }

    Ok(accumulator)
}
