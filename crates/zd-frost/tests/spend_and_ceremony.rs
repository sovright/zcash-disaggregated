//! Fixed-alpha spend signing and the full key ceremony, checked against
//! orchard's own key and signature types.

use std::collections::BTreeMap;

use orchard::keys::SpendValidatingKey;
use orchard::primitives::redpallas::{Signature as OrchardSig, SpendAuth, VerificationKey};
use pasta_curves::pallas;
use rand_core::{OsRng, RngCore};
use zd_frost::{
    Field, Identifier, PallasScalarField, SigningPackage,
    ceremony::{self, CeremonyConfig, CeremonyError, ParticipantKeys},
    keys::{EvenY, KeyPackage, PublicKeyPackage},
    spend::{self, SpendSignError},
};

fn random_alpha() -> pallas::Scalar {
    PallasScalarField::random(&mut OsRng)
}

fn random_sighash() -> [u8; 32] {
    let mut s = [0u8; 32];
    OsRng.fill_bytes(&mut s);
    s
}

/// Runs a fixed-alpha signing session with `signers` and returns the
/// 64-byte SpendAuthSig.
fn sign_spend(
    kps: &BTreeMap<Identifier, KeyPackage>,
    pkp: &PublicKeyPackage,
    signers: &[Identifier],
    sighash: [u8; 32],
    alpha: pallas::Scalar,
) -> [u8; 64] {
    let mut nonces = BTreeMap::new();
    let mut comms = BTreeMap::new();
    for id in signers {
        let (n, c) = spend::commit(&kps[id], sighash, alpha, &mut OsRng);
        nonces.insert(*id, n);
        comms.insert(*id, c);
    }
    let pkg = SigningPackage::new(comms, &sighash);
    let mut shares = BTreeMap::new();
    for (id, n) in nonces {
        shares.insert(id, spend::sign(n, &pkg, &kps[&id]).unwrap());
    }
    let sig = spend::aggregate(&pkg, &shares, pkp, alpha).unwrap();
    spend::signature_bytes(&sig)
}

/// Orchard's view of the spend: `rk = ak.randomize(alpha)` and verify.
fn orchard_verify(ak: [u8; 32], alpha: pallas::Scalar, sighash: &[u8; 32], sig: [u8; 64]) {
    let ak = SpendValidatingKey::from_bytes(&ak).expect("valid ak with even y");
    let rk: VerificationKey<SpendAuth> = ak.randomize(&alpha);
    rk.verify(sighash, &OrchardSig::from(sig))
        .expect("orchard verifies the spend auth signature under rk");
}

fn dealer_keys(n: u16, t: u16) -> (BTreeMap<Identifier, KeyPackage>, PublicKeyPackage) {
    let (shares, pkp) = zd_frost::keys::generate_with_dealer(
        n,
        t,
        zd_frost::keys::IdentifierList::Default,
        &mut OsRng,
    )
    .unwrap();
    let kps = shares
        .into_iter()
        .map(|(i, s)| (i, s.try_into().unwrap()))
        .collect();
    (kps, pkp)
}

fn ak_bytes(pkp: &PublicKeyPackage) -> [u8; 32] {
    pkp.verifying_key().serialize().unwrap().try_into().unwrap()
}

#[test]
fn fixed_alpha_signature_verifies_in_orchard() {
    for _ in 0..8 {
        let (kps, pkp) = dealer_keys(3, 2);
        let ids: Vec<_> = kps.keys().copied().collect();
        let alpha = random_alpha();
        let sighash = random_sighash();

        // Our rk equals orchard's rk.
        let rk = spend::randomized_verifying_key(pkp.verifying_key(), alpha);
        let orchard_rk: [u8; 32] = (&SpendValidatingKey::from_bytes(&ak_bytes(&pkp))
            .unwrap()
            .randomize(&alpha))
            .into();
        assert_eq!(rk.serialize().unwrap(), orchard_rk);

        // Any two of three.
        for pair in [[ids[0], ids[1]], [ids[1], ids[2]], [ids[0], ids[2]]] {
            let sig = sign_spend(&kps, &pkp, &pair, sighash, alpha);
            orchard_verify(ak_bytes(&pkp), alpha, &sighash, sig);
        }
    }
}

#[test]
fn signer_refuses_a_different_message() {
    let (kps, _) = dealer_keys(3, 2);
    let ids: Vec<_> = kps.keys().copied().collect();
    let alpha = random_alpha();
    let sighash = random_sighash();

    let (n0, c0) = spend::commit(&kps[&ids[0]], sighash, alpha, &mut OsRng);
    let (_, c1) = spend::commit(&kps[&ids[1]], sighash, alpha, &mut OsRng);
    let other = random_sighash();
    let pkg = SigningPackage::new([(ids[0], c0), (ids[1], c1)].into(), &other);
    assert!(matches!(
        spend::sign(n0, &pkg, &kps[&ids[0]]),
        Err(SpendSignError::MessageMismatch)
    ));
}

#[test]
fn wrong_alpha_is_caught_at_aggregation() {
    let (kps, pkp) = dealer_keys(3, 2);
    let ids: Vec<_> = kps.keys().copied().take(2).collect();
    let alpha = random_alpha();
    let sighash = random_sighash();

    let mut nonces = BTreeMap::new();
    let mut comms = BTreeMap::new();
    for id in &ids {
        // Second signer was handed a different alpha.
        let a = if *id == ids[0] { alpha } else { random_alpha() };
        let (n, c) = spend::commit(&kps[id], sighash, a, &mut OsRng);
        nonces.insert(*id, n);
        comms.insert(*id, c);
    }
    let pkg = SigningPackage::new(comms, &sighash);
    let shares: BTreeMap<_, _> = nonces
        .into_iter()
        .map(|(id, n)| (id, spend::sign(n, &pkg, &kps[&id]).unwrap()))
        .collect();
    let err = spend::aggregate(&pkg, &shares, &pkp, alpha).unwrap_err();
    assert_eq!(err.culprits(), vec![ids[1]]);
}

#[test]
fn alpha_encoding() {
    let a = random_alpha();
    let bytes = <PallasScalarField as Field>::serialize(&a);
    assert_eq!(spend::alpha_from_bytes(&bytes).unwrap(), a);
    assert!(matches!(
        spend::alpha_from_bytes(&[0xff; 32]),
        Err(SpendSignError::InvalidAlpha)
    ));
}

// ---------------------------------------------------------------------------
// Ceremony
// ---------------------------------------------------------------------------

fn configs(t: u16, ids: &[u16]) -> Vec<CeremonyConfig> {
    let transcript_id = zd_keys::ceremony::transcript_id(b"test ceremony params");
    ids.iter()
        .map(|me| CeremonyConfig {
            transcript_id,
            threshold: t,
            participants: ids.to_vec(),
            me: *me,
        })
        .collect()
}

/// Runs the whole ceremony in memory. `tamper` may edit round 2 messages in
/// flight: (sender, recipient, message).
fn run_ceremony(
    t: u16,
    ids: &[u16],
    tamper: impl Fn(u16, u16, &mut ceremony::Round2Message),
) -> Result<BTreeMap<u16, ParticipantKeys>, CeremonyError> {
    let mut r1_states = BTreeMap::new();
    let mut r1_msgs = BTreeMap::new();
    for cfg in configs(t, ids) {
        let me = cfg.me;
        let (s, m) = ceremony::start(cfg, &mut OsRng)?;
        r1_states.insert(me, s);
        r1_msgs.insert(me, m);
    }

    let mut r2_states = BTreeMap::new();
    let mut inbox: BTreeMap<u16, BTreeMap<u16, ceremony::Round2Message>> = BTreeMap::new();
    for (me, s) in r1_states {
        let received = r1_msgs
            .iter()
            .filter(|(i, _)| **i != me)
            .map(|(i, m)| (*i, m.clone()))
            .collect();
        let (s2, out) = s.round2(&received)?;
        r2_states.insert(me, s2);
        for (to, mut msg) in out {
            tamper(me, to, &mut msg);
            inbox.entry(to).or_default().insert(me, msg);
        }
    }

    let mut keys = BTreeMap::new();
    for (me, s) in r2_states {
        keys.insert(me, s.finish(&inbox[&me])?);
    }
    Ok(keys)
}

#[test]
fn ceremony_produces_one_quantum_recoverable_account() {
    let ids = [1u16, 2, 3];
    // Enough runs that both ỹ(ak) cases occur with near certainty.
    for _ in 0..12 {
        let keys = run_ceremony(2, &ids, |_, _, _| {}).unwrap();

        // Confirmation round.
        let hashes: BTreeMap<u16, [u8; 32]> =
            keys.iter().map(|(i, k)| (*i, k.fvk_hash())).collect();
        for (me, k) in &keys {
            let others = hashes
                .iter()
                .filter(|(i, _)| *i != me)
                .map(|(i, h)| (*i, *h))
                .collect();
            k.check_confirmations(&ids, *me, &others).unwrap();
        }

        let first = &keys[&1];
        let pkp = first.public_key_package().clone();
        assert!(pkp.has_even_y());
        let ak = ak_bytes(&pkp);
        assert_eq!(first.account().ak(), &ak);
        assert_eq!(first.account().fvk().to_bytes()[..32], ak);

        // Everyone has the same sk, qsk and account; the qk path is ZIP 2005.
        for k in keys.values() {
            assert_eq!(k.sk().as_bytes(), first.sk().as_bytes());
            assert_eq!(k.qsk().as_bytes(), first.qsk().as_bytes());
            assert_eq!(k.public_key_package(), &pkp);
            assert_eq!(k.account().qk(), &zd_keys::zip2005::qk(k.qsk()));
            assert_eq!(
                k.account().nk(),
                zd_keys::zip2005::nk(first.sk().as_bytes())
            );
        }

        // Rebuilding from wallet-state parts gives the same FVK.
        let host = zd_keys::AccountKeys::from_host_parts(
            ak,
            first.account().nk(),
            first.account().qk().clone(),
        )
        .unwrap();
        assert_eq!(host.fvk_hash(), first.fvk_hash());

        // Any two participants can authorize a spend under a PCZT alpha.
        let kps: BTreeMap<Identifier, KeyPackage> = keys
            .values()
            .map(|k| (*k.key_package().identifier(), k.key_package().clone()))
            .collect();
        let signers: Vec<_> = kps.keys().copied().skip(1).collect();
        let alpha = random_alpha();
        let sighash = random_sighash();
        let sig = sign_spend(&kps, &pkp, &signers, sighash, alpha);
        orchard_verify(ak, alpha, &sighash, sig);
    }
}

#[test]
fn ceremony_3_of_5() {
    let ids = [1u16, 2, 3, 4, 5];
    let keys = run_ceremony(3, &ids, |_, _, _| {}).unwrap();
    let pkp = keys[&1].public_key_package().clone();
    let kps: BTreeMap<Identifier, KeyPackage> = keys
        .values()
        .map(|k| (*k.key_package().identifier(), k.key_package().clone()))
        .collect();
    let signers: Vec<_> = kps.keys().copied().step_by(2).collect();
    assert_eq!(signers.len(), 3);
    let alpha = random_alpha();
    let sighash = random_sighash();
    let sig = sign_spend(&kps, &pkp, &signers, sighash, alpha);
    orchard_verify(ak_bytes(&pkp), alpha, &sighash, sig);
}

#[test]
fn ceremony_rejects_changed_sk_reveal() {
    let err = run_ceremony(2, &[1, 2, 3], |from, to, m| {
        if from == 2 && to == 3 {
            m.sk_reveal[0] ^= 1;
        }
    })
    .err()
    .expect("tampered reveal must fail");
    assert!(matches!(
        err,
        CeremonyError::SharedSk(zd_keys::ceremony::CeremonyError::BadReveal(2))
    ));
}

#[test]
fn ceremony_rejects_bad_params() {
    let bad = |t, ids: &[u16], me| CeremonyConfig {
        transcript_id: [0; 32],
        threshold: t,
        participants: ids.to_vec(),
        me,
    };
    for cfg in [
        bad(1, &[1, 2, 3], 1),
        bad(4, &[1, 2, 3], 1),
        bad(2, &[1, 2, 2], 1),
        bad(2, &[0, 1, 2], 1),
        bad(2, &[1, 2, 3], 4),
    ] {
        assert!(matches!(
            ceremony::start(cfg, &mut OsRng),
            Err(CeremonyError::InvalidParams(_))
        ));
    }
}

#[test]
fn confirmation_mismatch_is_detected() {
    let keys = run_ceremony(2, &[1, 2, 3], |_, _, _| {}).unwrap();
    let mut others: BTreeMap<u16, [u8; 32]> = [(2, keys[&2].fvk_hash()), (3, [0u8; 32])].into();
    assert!(matches!(
        keys[&1].check_confirmations(&[1, 2, 3], 1, &others),
        Err(CeremonyError::ConfirmationMismatch(3))
    ));
    others.remove(&3);
    assert!(matches!(
        keys[&1].check_confirmations(&[1, 2, 3], 1, &others),
        Err(CeremonyError::Missing(3))
    ));
}
