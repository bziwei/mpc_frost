#![allow(non_snake_case)]

pub async fn algo_sign(
    keystore: &KeyStore,
    my_signer_id: u16,
    n_signers: u16,
    derv_path: &str,
    tx_hash: &[u8],
) -> Outcome<Signature> {
    assert_throw!(tx_hash.len() <= 64);
    let my_member_id = keystore.member_id;
    let mut round: &str;

    round = "member_id";
    send_bcast(my_signer_id, round, &my_member_id)
        .await
        .catch_()?;
    let signer_member_ids: Vec<u16> = recv_bcast(n_signers, round).await.catch_()?;
    let _smi: HashSet<u16> = signer_member_ids.iter().cloned().collect();

    assert_throw!(
        signer_member_ids.len() == _smi.len(),
        &format!("Signers reported member_id: {signer_member_ids:?}")
    );
    println!("Finished exchanging member_id");

    // #region Derive child keys
    let mut signing_key = keystore.signing_key.clone();
    let mut valid_com_vec = keystore.valid_com_vec.clone();
    let y_sum_bytes_small = signing_key.group_public.compress().to_bytes().to_vec();
    let chain_code: [u8; 32] = Sha512::digest(&y_sum_bytes_small)
        .get(..32)
        .ifnone_()?
        .try_into()
        .unwrap();
    let (tweak_sk, child_pk) = match derv_path.is_empty() {
        true => (Scalar::zero(), signing_key.group_public),
        false => hd::algo_get_hd_key(derv_path, &signing_key.group_public, &chain_code).catch_()?,
    };
    signing_key.group_public = child_pk;
    signing_key.x_i += &tweak_sk;
    signing_key.g_x_i += &constants::RISTRETTO_BASEPOINT_TABLE * &tweak_sk;
    valid_com_vec[signer_member_ids[0] as usize - 1]
        .shares_commitment
        .commitment[0] += &constants::RISTRETTO_BASEPOINT_TABLE * &tweak_sk;
    println!("Finished non-hardened derivation.");
    // #endregion

    // #region round 2: broadcast signing commitment pairs
    let mut rng = OsRng;
    let _obj: _ = KeyPair::sign_preprocess(1, my_member_id, &mut rng).catch_()?;
    let signing_com_pair: Vec<SigningCommitmentPair> = _obj.0;
    let mut signing_nonce_pair: Vec<SigningNoncePair> = _obj.1;

    round = "signing_com_pair";
    send_bcast(my_signer_id, round, &signing_com_pair[0])
        .await
        .catch_()?;
    let signing_com_pair_vec: Vec<SigningCommitmentPair> =
        recv_bcast(n_signers, round).await.catch_()?;
    println!("Finish sign round {round}");
    // #endregion

    // #region round 3: broadcast signing response
    round = "response";
    let response: SigningResponse = signing_key
        .sign_and_respond(&signing_com_pair_vec, &mut signing_nonce_pair, tx_hash)
        .catch_()?;
    send_bcast(my_signer_id, round, &response).await.catch_()?;
    let response_vec: Vec<SigningResponse> = recv_bcast(n_signers, round).await.catch_()?;
    println!("Finished sign round {round}");
    // #endregion

    // #region: combine signature shares and verify
    let mut signer_pubkeys: HashMap<u16, RistrettoPoint> =
        HashMap::with_capacity(signing_com_pair_vec.len());
    for counter in 0..signing_com_pair_vec.len() {
        let ith_pubkey = get_ith_pubkey(signer_member_ids[counter], &valid_com_vec);
        let _ = signer_pubkeys.insert(signer_member_ids[counter], ith_pubkey);
    }
    let group_sig: Signature = KeyPair::sign_aggregate_responses(
        tx_hash,
        &signing_com_pair_vec,
        &response_vec,
        &signer_pubkeys,
    )
    .catch_()?;
    validate(&group_sig, &signing_key.group_public).catch_()?;
    // verify_solana(&group_sig, &signing_key.group_public).catch_()?;
    println!("Validated signature");
    // #endregion

    Ok(group_sig)
}

pub fn verify_solana(sig: &Signature, pk: &RistrettoPoint) -> Outcome<()> {
    use ed25519_dalek::Signature as LibSignature;
    let msg = &sig.hash;
    let pk = {
        let pk_bytes = pk.to_bytes();
        let pk = ed25519_dalek::PublicKey::from_bytes(&pk_bytes).catch_()?;
        pk
    };
    let sig = {
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&sig.r.to_bytes());
        sig_bytes[32..].copy_from_slice(&sig.z.to_bytes());
        let sig = LibSignature::from_bytes(&sig_bytes).catch_()?;
        sig
    };

    pk.verify_strict(msg, &sig).catch_()?;
    Ok(())
}

use bip32::PublicKey;
use curve25519_dalek::{constants, ristretto::RistrettoPoint, scalar::Scalar};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use std::collections::{HashMap, HashSet};

use super::{hd, keygen::KeyStore};
use crate::party_i::{
    get_ith_pubkey, validate, KeyPair, Signature, SigningCommitmentPair, SigningNoncePair,
    SigningResponse,
};
use crate::prelude::*;
