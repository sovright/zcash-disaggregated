//! The ciphersuite: frost-core's generic checks, agreement with orchard's
//! RedPallas, and byte-for-byte agreement with the upstream `reddsa` 0.5.2
//! ciphersuite.

use std::collections::BTreeMap;

use group::GroupEncoding;
use orchard::primitives::redpallas::{self as orchard_redpallas, SpendAuth};
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, RngCore, SeedableRng};
use zd_frost::{
    Ciphersuite, Field, Group, GroupError, PallasBlake2b512, PallasGroup, PallasScalarField, frost,
    keys::EvenY,
};

use reddsa_upstream::frost::redpallas as upstream;

#[test]
fn generic_sign_with_dealer() {
    frost::tests::ciphersuite_generic::check_sign_with_dealer::<PallasBlake2b512, _>(OsRng);
}

#[test]
fn generic_sign_with_dkg() {
    frost::tests::ciphersuite_generic::check_sign_with_dkg::<PallasBlake2b512, _>(OsRng);
}

#[test]
fn generic_randomized_sign_with_dealer() {
    let (msg, sig, rk) = zd_frost::frost_rerandomized::tests::check_randomized_sign_with_dealer::<
        PallasBlake2b512,
        _,
    >(OsRng);
    let rk: [u8; 32] = rk.serialize().unwrap().try_into().unwrap();
    let sig: [u8; 64] = sig.serialize().unwrap().try_into().unwrap();
    let vk = orchard_redpallas::VerificationKey::<SpendAuth>::try_from(rk).unwrap();
    vk.verify(&msg, &orchard_redpallas::Signature::from(sig))
        .expect("orchard accepts the FROST signature");
}

#[test]
fn generic_error_culprit_and_identifiers() {
    frost::tests::ciphersuite_generic::check_error_culprit::<PallasBlake2b512>();
    frost::tests::ciphersuite_generic::check_identifier_derivation::<PallasBlake2b512>();
}

#[test]
fn generator_is_orchard_spendauth_basepoint() {
    use pasta_curves::arithmetic::CurveExt;
    // GroupHash^P("z.cash:Orchard", "G")
    let g = pasta_curves::pallas::Point::hash_to_curve("z.cash:Orchard")(b"G");
    assert_eq!(g.to_bytes(), zd_frost::SPENDAUTH_BASEPOINT_BYTES);

    // [ask] G must match orchard's own ak for the same scalar.
    let mut rng = OsRng;
    for _ in 0..8 {
        let ask = PallasScalarField::random(&mut rng);
        let ours = PallasGroup::serialize(&(PallasGroup::generator() * ask)).unwrap();
        let sk = orchard_redpallas::SigningKey::<SpendAuth>::try_from(
            <PallasScalarField as Field>::serialize(&ask),
        )
        .unwrap();
        let theirs: [u8; 32] = (&orchard_redpallas::VerificationKey::from(&sk)).into();
        assert_eq!(ours, theirs);
    }
}

#[test]
fn identity_is_rejected() {
    let id = PallasGroup::identity();
    assert_eq!(
        PallasGroup::serialize(&id),
        Err(GroupError::InvalidIdentityElement)
    );
    assert_eq!(
        PallasGroup::deserialize(&id.to_bytes()),
        Err(GroupError::InvalidIdentityElement)
    );
}

#[test]
fn non_canonical_point_is_rejected() {
    // x = p + 3: maps to a valid point if reduced, so it must be refused.
    let enc: [u8; 32] =
        hex::decode("04000000ed302d991bf94c09fc98462200000000000000000000000000000040")
            .unwrap()
            .try_into()
            .unwrap();
    assert_eq!(
        PallasGroup::deserialize(&enc),
        Err(GroupError::MalformedElement)
    );
}

#[test]
fn dealer_keys_have_even_y() {
    for _ in 0..16 {
        let (shares, pkp) = zd_frost::keys::generate_with_dealer(
            3,
            2,
            zd_frost::keys::IdentifierList::Default,
            &mut OsRng,
        )
        .unwrap();
        assert!(pkp.has_even_y());
        for s in shares.into_values() {
            let kp: zd_frost::keys::KeyPackage = s.try_into().unwrap();
            assert!(kp.has_even_y());
        }
    }
}

/// Same RNG stream into ours and upstream's ciphersuite: every serialized
/// output must be identical. This is what lets us switch to the upstream
/// crate later without migrating key material.
#[test]
fn byte_identical_to_upstream_reddsa() {
    assert_eq!(
        <PallasBlake2b512 as Ciphersuite>::ID,
        <upstream::PallasBlake2b512 as upstream::Ciphersuite>::ID
    );

    for seed in 0u8..8 {
        let mut ours_rng = ChaCha20Rng::from_seed([seed; 32]);
        let mut up_rng = ChaCha20Rng::from_seed([seed; 32]);

        // Key generation.
        let (ours_shares, ours_pkp) = zd_frost::keys::generate_with_dealer(
            3,
            2,
            zd_frost::keys::IdentifierList::Default,
            &mut ours_rng,
        )
        .unwrap();
        let (up_shares, up_pkp) = upstream::keys::generate_with_dealer(
            3,
            2,
            upstream::keys::IdentifierList::Default,
            &mut up_rng,
        )
        .unwrap();
        assert_eq!(ours_pkp.serialize().unwrap(), up_pkp.serialize().unwrap());

        let ours_kps: BTreeMap<_, zd_frost::keys::KeyPackage> = ours_shares
            .into_iter()
            .map(|(i, s)| (i.serialize(), s.try_into().unwrap()))
            .collect();
        let up_kps: BTreeMap<_, upstream::keys::KeyPackage> = up_shares
            .into_iter()
            .map(|(i, s)| (i.serialize(), s.try_into().unwrap()))
            .collect();
        for (i, kp) in &ours_kps {
            assert_eq!(kp.serialize().unwrap(), up_kps[i].serialize().unwrap());
        }

        // Signing with two of three.
        let mut msg = [0u8; 32];
        ours_rng.fill_bytes(&mut msg);
        up_rng.fill_bytes(&mut [0u8; 32]);
        let signers: Vec<_> = ours_kps.keys().take(2).cloned().collect();

        let mut ours_nonces = BTreeMap::new();
        let mut ours_comms = BTreeMap::new();
        let mut up_nonces = BTreeMap::new();
        let mut up_comms = BTreeMap::new();
        for i in &signers {
            let (n, c) = frost::round1::commit(ours_kps[i].signing_share(), &mut ours_rng);
            ours_nonces.insert(*ours_kps[i].identifier(), n);
            ours_comms.insert(*ours_kps[i].identifier(), c);
            let (n, c) = upstream::round1::commit(up_kps[i].signing_share(), &mut up_rng);
            up_nonces.insert(*up_kps[i].identifier(), n);
            up_comms.insert(*up_kps[i].identifier(), c);
        }
        let ours_pkg = zd_frost::SigningPackage::new(ours_comms, &msg);
        let up_pkg = upstream::SigningPackage::new(up_comms, &msg);
        assert_eq!(ours_pkg.serialize().unwrap(), up_pkg.serialize().unwrap());

        let mut ours_sigs = BTreeMap::new();
        let mut up_sigs = BTreeMap::new();
        for i in &signers {
            let id = *ours_kps[i].identifier();
            let s = frost::round2::sign(&ours_pkg, &ours_nonces[&id], &ours_kps[i]).unwrap();
            let uid = *up_kps[i].identifier();
            let u = upstream::round2::sign(&up_pkg, &up_nonces[&uid], &up_kps[i]).unwrap();
            assert_eq!(s.serialize(), u.serialize());
            ours_sigs.insert(id, s);
            up_sigs.insert(uid, u);
        }
        let ours_sig = frost::aggregate(&ours_pkg, &ours_sigs, &ours_pkp).unwrap();
        let up_sig = upstream::aggregate(&up_pkg, &up_sigs, &up_pkp).unwrap();
        assert_eq!(ours_sig.serialize().unwrap(), up_sig.serialize().unwrap());
    }
}
