//! Cross-checks the ZIP 2005 derivations against `orchard`, and exercises the
//! quantum-recoverable account path end to end.

use std::collections::BTreeMap;

use ff::{Field, PrimeField};
use orchard::keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendValidatingKey, SpendingKey};
use orchard::primitives::redpallas::{Signature, SigningKey, SpendAuth};
use pasta_curves::pallas;
use rand_core::Rng;
use zd_keys::{AccountKeys, Error, ceremony, zip2005};

fn random_sk(rng: &mut impl Rng) -> ([u8; 32], SpendingKey) {
    loop {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        if let Some(sk) = Option::from(SpendingKey::from_bytes(b)) {
            return (b, sk);
        }
    }
}

/// Our PRF^expand, ToBase, ToScalar and sign normalization must agree with
/// orchard's own legacy derivation from a spending key.
#[test]
fn legacy_derivations_match_orchard() {
    let mut rng = rand::rng();
    for _ in 0..32 {
        let (bytes, sk) = random_sk(&mut rng);
        let fvk = FullViewingKey::from(&sk).to_bytes();

        let (_, ak) = zip2005::normalize_ask(zip2005::legacy_ask(&bytes)).unwrap();
        assert_eq!(ak, fvk[..32], "ak");
        assert_eq!(zip2005::nk(&bytes).to_repr(), fvk[32..64], "nk");
        assert_eq!(zip2005::legacy_rivk(&bytes).to_repr(), fvk[64..], "rivk");

        let svk = SpendValidatingKey::from(&SpendAuthorizingKey::from(&sk));
        assert_eq!(svk.to_bytes(), ak);
    }
}

#[test]
fn qk_is_blake3_derive_key() {
    let qsk = zd_keys::Qsk::from_bytes([0x42; 32]);
    let expected = blake3::derive_key("Zcash ZIP 2005 qk-derivation v1", &[0x42; 32]);
    assert_eq!(zip2005::qk(&qsk).as_bytes(), &expected);
}

/// HSM-style 1/1 signer: `ask` generated outside any seed, account built on
/// the use_qsk path, and a randomized spend signature from that `ask`
/// verifies under the FVK's `ak`.
#[test]
fn hsm_account_signs_for_its_fvk() {
    let mut rng = rand::rng();
    let (ask, ak) = zip2005::normalize_ask(pallas::Scalar::random(&mut rng)).unwrap();
    let (sk, _) = random_sk(&mut rng);

    let (keys, qsk) = AccountKeys::derive(&sk, ak).unwrap();
    assert_eq!(keys.qk(), &zip2005::qk(&qsk));
    assert_eq!(&keys.fvk().to_bytes()[..32], &ak);
    assert_ne!(
        keys.rivk(),
        zip2005::legacy_rivk(&sk),
        "must not be the legacy rivk"
    );

    // Addresses come out and map back to their diversifier index.
    let ivk = keys.fvk().to_ivk(Scope::External);
    for j in [0u64, 1, 1 << 40] {
        let addr = keys.fvk().address_at(j, Scope::External);
        assert_eq!(keys.fvk().scope_for_address(&addr), Some(Scope::External));
        assert!(ivk.diversifier_index(&addr).is_some());
    }

    // Randomized spend authorization, as in a real Action.
    let alpha = pallas::Scalar::random(&mut rng);
    let sighash = [7u8; 32];
    let rsk = SigningKey::<SpendAuth>::try_from(ask.to_repr())
        .unwrap()
        .randomize(&alpha);
    let sig: Signature<SpendAuth> = rsk.sign(&mut rng, &sighash);
    let rk = SpendValidatingKey::from(keys.fvk().clone()).randomize(&alpha);
    assert!(rk.verify(&sighash, &sig).is_ok());
    let wrong =
        SpendValidatingKey::from(keys.fvk().clone()).randomize(&(alpha + pallas::Scalar::ONE));
    assert!(wrong.verify(&sighash, &sig).is_err());
}

/// rivk_ext binds qk: different sk (hence qsk) with the same ak gives a
/// different account, and wallet state can rebuild the account from
/// (ak, nk, qk) alone.
#[test]
fn rivk_binds_qk_and_host_rebuild_matches() {
    let mut rng = rand::rng();
    let (_, ak) = zip2005::normalize_ask(pallas::Scalar::random(&mut rng)).unwrap();
    let (sk1, _) = random_sk(&mut rng);
    let (sk2, _) = random_sk(&mut rng);
    let (a, _) = AccountKeys::derive(&sk1, ak).unwrap();
    let (b, _) = AccountKeys::derive(&sk2, ak).unwrap();
    assert_ne!(a.rivk(), b.rivk());
    assert_ne!(a.fvk_hash(), b.fvk_hash());

    let rebuilt = AccountKeys::from_host_parts(ak, a.nk(), a.qk().clone()).unwrap();
    assert_eq!(rebuilt.fvk(), a.fvk());
}

#[test]
fn rejects_ak_with_odd_y() {
    let mut rng = rand::rng();
    let (_, mut ak) = zip2005::normalize_ask(pallas::Scalar::random(&mut rng)).unwrap();
    ak[31] |= 0x80;
    let (sk, _) = random_sk(&mut rng);
    assert_eq!(AccountKeys::derive(&sk, ak).err(), Some(Error::InvalidAk));
    assert_eq!(
        AccountKeys::derive(&sk, [0u8; 32]).err(),
        Some(Error::InvalidAk)
    );
}

#[test]
fn commit_reveal_ceremony() {
    let mut rng = rand::rng();
    let tid = ceremony::transcript_id(b"params: 2-of-3 testnet");
    let ids = [1u32, 2, 3];
    let mut contributions = BTreeMap::new();
    for id in ids {
        let mut c = [0u8; 32];
        rng.fill_bytes(&mut c);
        contributions.insert(id, c);
    }
    let commits: BTreeMap<_, _> = contributions
        .iter()
        .map(|(id, c)| (*id, ceremony::commit(&tid, *id, c)))
        .collect();

    // Every participant computes the same sk regardless of list order.
    let a = ceremony::combine(&tid, &[1, 2, 3], &commits, &contributions).unwrap();
    let b = ceremony::combine(&tid, &[3, 1, 2], &commits, &contributions).unwrap();
    assert_eq!(a.as_bytes(), b.as_bytes());

    // A different transcript gives a different sk.
    let tid2 = ceremony::transcript_id(b"other");
    let commits2: BTreeMap<_, _> = contributions
        .iter()
        .map(|(id, c)| (*id, ceremony::commit(&tid2, *id, c)))
        .collect();
    let c = ceremony::combine(&tid2, &ids, &commits2, &contributions).unwrap();
    assert_ne!(a.as_bytes(), c.as_bytes());

    // A changed reveal, or a missing one, is caught.
    let mut bad = contributions.clone();
    bad.get_mut(&2).unwrap()[0] ^= 1;
    assert_eq!(
        ceremony::combine(&tid, &ids, &commits, &bad).err(),
        Some(ceremony::CeremonyError::BadReveal(2))
    );
    let mut missing = contributions.clone();
    missing.remove(&3);
    assert_eq!(
        ceremony::combine(&tid, &ids, &commits, &missing).err(),
        Some(ceremony::CeremonyError::MissingReveal(3))
    );
    assert_eq!(
        ceremony::combine(&tid, &[1, 2], &commits, &contributions).err(),
        Some(ceremony::CeremonyError::UnknownParticipant(3))
    );

    // The shared sk feeds a valid account.
    let (_, ak) = zip2005::normalize_ask(pallas::Scalar::random(&mut rng)).unwrap();
    assert!(AccountKeys::derive(a.as_bytes(), ak).is_ok());
}
