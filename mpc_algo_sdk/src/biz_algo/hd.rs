pub fn algo_get_hd_key(
    derivation_path: &str,
    parent_pk: &RistrettoPoint,
    chain_code: &ChainCode,
) -> Outcome<HdKey> {
    let HDE = "HierarchicalDerivationException";
    let path = DerivationPath::from_str(derivation_path).catch(
        HDE,
        &format!(
            "String \"{}\" is not a valid derivation path",
            derivation_path
        ),
    )?;
    let encoded_par_pk = parent_pk.compress().to_bytes();
    let par_pk_bytes: &[u8] = encoded_par_pk.as_ref();
    assert_throw!(par_pk_bytes.len() == 32 /* formerly 33 */);

    let mut ex_pk = ExtendedKey {
        prefix: Prefix::XPUB,
        attrs: ExtendedKeyAttrs {
            parent_fingerprint: [0u8; 4],
            child_number: ChildNumber(0u32),
            chain_code: *chain_code,
            depth: 0u8,
        },
        key_bytes: par_pk_bytes.try_into().unwrap(),
    };
    let mut pk = XPub::try_from(ex_pk.clone()).catch(
        HDE,
        &format!("Cannot create XPub from ex_pk_b58={}", &ex_pk.to_string()),
    )?;
    let ex_sk = ExtendedKey {
        prefix: Prefix::XPRV,
        attrs: ExtendedKeyAttrs {
            parent_fingerprint: [0u8; 4],
            child_number: ChildNumber(0u32),
            chain_code: *chain_code,
            depth: 0u8,
        },
        // key_bytes: [
        //     1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        //     0, 0,
        // ],
        key_bytes: Scalar::one().to_bytes(), // equivalent to the above byte array
    };
    let scalar_one = XPrv::try_from(ex_sk.clone()).catch(
        HDE,
        &format!("Cannot create XPrv from ex_sk_b58={}", &ex_sk.to_string()),
    )?;
    let mut total_tweak = scalar_one.private_key().clone();
    for ccnum in path.as_ref() {
        let depth: u8 = pk
            .attrs()
            .depth
            .checked_add(1)
            .ifnone(HDE, "due to depth")?;
        let mut hmac: HmacSha512 =
            HmacSha512::new_from_slice(&pk.attrs().chain_code).catch(HDE, "due to crypto")?;
        assert_throw!(
            false == ccnum.is_hardened(),
            HDE,
            "Hardened derivation is too difficult for MPC signature."
        );
        hmac.update(&pk.public_key().to_bytes());
        hmac.update(&ccnum.to_bytes());
        let result = hmac.finalize().into_bytes();
        let (tweak, chain_code) = result.split_at(KEY_SIZE);
        assert_throw!(tweak.len() == 32);
        assert_throw!(chain_code.len() == 32);
        let public_key = pk.public_key().derive_child(tweak.try_into().unwrap());
        total_tweak = total_tweak.derive_child(tweak.try_into().unwrap());

        ex_pk = ExtendedKey {
            prefix: Prefix::XPUB,
            attrs: ExtendedKeyAttrs {
                parent_fingerprint: pk.public_key().fingerprint(),
                child_number: *ccnum,
                chain_code: chain_code.try_into().unwrap(),
                depth,
            },
            key_bytes: {
                let pk_bytes = public_key.to_bytes();
                assert_throw!(pk_bytes.len() == 32 /* formerly 33 */);
                let key_bytes = pk_bytes.try_into().unwrap();
                key_bytes
            },
        };

        pk = XPub::try_from(ex_pk).catch(HDE, "")?;
    }

    let tweak_sk: Scalar = Scalar::from_bytes_mod_order(total_tweak.to_bytes()) - Scalar::one();
    let child_pk: RistrettoPoint = CompressedRistretto::from_slice(&pk.public_key().to_bytes())
        .decompress()
        .ifnone(HDE, "Failed to deserialize")?;

    Ok((tweak_sk, child_pk))
}

use bip32::{
    ChainCode, ChildNumber, DerivationPath, ExtendedKey, ExtendedKeyAttrs, Prefix, PrivateKey,
    PublicKey, XPrv, XPub, KEY_SIZE,
};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha512;
use std::{convert::TryInto, str::FromStr};

use crate::prelude::*;

type HmacSha512 = Hmac<Sha512>;
type HdKey = (Scalar, RistrettoPoint);
