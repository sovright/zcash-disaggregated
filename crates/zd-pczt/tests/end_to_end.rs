//! A 2-of-3 FROST account from the key ceremony receives an Ironwood note and
//! spends it through a PCZT: wallet state builds it, a prover proves it, the
//! quorum signs it under the PCZT's alpha, and the transaction extracts (which
//! verifies the proof and every signature).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use orchard::tree::MerkleHashOrchard;
use pczt::Pczt;
use pczt::roles::{
    creator::Creator, io_finalizer::IoFinalizer, tx_extractor::TransactionExtractor,
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use rand_core_06::OsRng;
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use zcash_note_encryption::try_note_decryption;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding, PcztResult},
    fees::zip317,
};
use zcash_protocol::{
    consensus::BlockHeight,
    memo::{Memo, MemoBytes},
    value::Zatoshis,
};
use zd_frost::{
    Identifier,
    ceremony::{self, CeremonyConfig, ParticipantKeys},
    keys::KeyPackage,
};
use zd_pczt::{Error, ValuePool, frost};

fn ironwood_pk() -> &'static orchard::circuit::ProvingKey {
    static PK: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();
    PK.get_or_init(|| {
        orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3)
    })
}

fn network() -> zcash_protocol::local_consensus::LocalNetwork {
    let h = |n| Some(BlockHeight::from_u32(n));
    zcash_protocol::local_consensus::LocalNetwork {
        overwinter: h(1),
        sapling: h(2),
        blossom: h(3),
        heartwood: h(4),
        canopy: h(5),
        nu5: h(6),
        nu6: h(7),
        nu6_1: h(8),
        nu6_2: h(9),
        nu6_3: h(10),
        nu7: None,
    }
}

fn run_ceremony() -> BTreeMap<u16, ParticipantKeys> {
    let ids = [1u16, 2, 3];
    let transcript_id = zd_keys::ceremony::transcript_id(b"e2e");
    let mut r1 = BTreeMap::new();
    let mut b1 = BTreeMap::new();
    for me in ids {
        let cfg = CeremonyConfig {
            transcript_id,
            threshold: 2,
            participants: ids.to_vec(),
            me,
        };
        let (s, m) = ceremony::start(cfg, &mut OsRng).unwrap();
        r1.insert(me, s);
        b1.insert(me, m);
    }
    let mut r2 = BTreeMap::new();
    let mut inbox: BTreeMap<u16, BTreeMap<u16, _>> = BTreeMap::new();
    for (me, s) in r1 {
        let rx = b1
            .iter()
            .filter(|(i, _)| **i != me)
            .map(|(i, m)| (*i, m.clone()))
            .collect();
        let (s2, out) = s.round2(&rx).unwrap();
        r2.insert(me, s2);
        for (to, m) in out {
            inbox.entry(to).or_default().insert(me, m);
        }
    }
    r2.into_iter()
        .map(|(me, s)| (me, s.finish(&inbox[&me]).unwrap()))
        .collect()
}

/// Wallet state's job: a PCZT spending one Ironwood note of the account.
fn build_pczt(fvk: &orchard::keys::FullViewingKey) -> Pczt {
    let mut rng = UnwrapErr(SysRng);
    let ivk = fvk.to_ivk(orchard::keys::Scope::External);
    let recipient = fvk.address_at(0u32, orchard::keys::Scope::External);

    // Receive an Ironwood (v3, quantum-recoverable) note; the detector's view.
    let note = {
        let v = orchard::bundle::BundleVersion::ironwood_v3();
        let mut b = orchard::builder::Builder::new(
            orchard::builder::BundleType::DEFAULT,
            v,
            v.default_flags(),
            orchard::Anchor::empty_tree(),
        )
        .unwrap();
        b.add_output(
            None,
            recipient,
            orchard::value::NoteValue::from_raw(1_000_000),
            Memo::Empty.encode().into_bytes(),
        )
        .unwrap();
        let (bundle, meta) = b.build::<i64>(&mut rng).unwrap().unwrap();
        let action = &bundle.actions()[meta.output_action_index(0).unwrap()];
        let domain = orchard::note_encryption::IronwoodDomain::for_action(action);
        let (note, _, _) = try_note_decryption(&domain, &ivk.prepare(), action)
            .expect("account IVK decrypts its Ironwood note");
        assert_eq!(note.version(), orchard::note::NoteVersion::V3);
        note
    };

    let (anchor, merkle_path): (orchard::Anchor, orchard::tree::MerklePath) = {
        let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        let mut tree =
            ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
        tree.append(leaf, incrementalmerkletree::Retention::Marked)
            .unwrap();
        tree.checkpoint(9_999_999).unwrap();
        let path = tree
            .witness_at_checkpoint_depth(0.into(), 0)
            .unwrap()
            .unwrap();
        let anchor = path.root(leaf);
        (anchor.into(), path.into())
    };

    let mut builder = Builder::new(
        network(),
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_ironwood_spend::<zip317::FeeRule>(fvk.clone(), note, merkle_path)
        .unwrap();
    builder
        .add_ironwood_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(orchard::keys::Scope::External)),
            fvk.address_at(7u32, orchard::keys::Scope::External),
            Zatoshis::const_from_u64(990_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult { pczt_parts, .. } = builder
        .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
        .unwrap();
    let unfinalized = Creator::build_from_parts(pczt_parts).unwrap();

    // Signers must refuse a PCZT that still has dummy keys.
    let ak: [u8; 32] = fvk.to_bytes()[..32].try_into().unwrap();
    assert!(matches!(
        zd_pczt::signing_request(&unfinalized, &ak),
        Err(Error::DummyKeysPresent)
    ));

    IoFinalizer::new(unfinalized)
        .finalize_io(UnwrapErr(SysRng))
        .unwrap()
}

#[test]
fn frost_quorum_spends_ironwood_note() {
    let keys = run_ceremony();
    let account = keys[&1].account();
    let ak = *account.ak();
    let pkp = keys[&1].public_key_package().clone();

    let pczt = build_pczt(account.fvk());

    // Signer side: find our spends. Exactly one; padding dummies are not ours.
    let request = zd_pczt::signing_request(&pczt, &ak).unwrap();
    assert_eq!(request.spends.len(), 1);
    assert_eq!(request.spends[0].pool, ValuePool::Ironwood);

    // A different account has nothing to sign here.
    let other = run_ceremony();
    assert!(matches!(
        zd_pczt::signing_request(&pczt, other[&1].account().ak()),
        Err(Error::NothingToSign)
    ));

    // Prover and signers work in parallel on the same PCZT.
    let proved = zd_pczt::prove(
        pczt.clone(),
        None,
        Some(ironwood_pk()),
        &mut UnwrapErr(SysRng),
    )
    .unwrap();

    // FROST with participants 1 and 3.
    let signers: BTreeMap<Identifier, &KeyPackage> = [1u16, 3]
        .iter()
        .map(|i| {
            let kp = keys[i].key_package();
            (*kp.identifier(), kp)
        })
        .collect();
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for (id, kp) in &signers {
        // Each signer derives the request itself from the PCZT it was sent.
        let req = zd_pczt::signing_request(&pczt, &ak).unwrap();
        let (n, c) = frost::commit(kp, &req, &mut OsRng);
        nonces.insert(*id, n);
        commitments.insert(*id, c);
    }
    let packages = frost::signing_packages(&request, &commitments);
    let mut shares = BTreeMap::new();
    for (id, n) in nonces {
        shares.insert(id, frost::sign(n, &packages, signers[&id]).unwrap());
    }
    let sigs = frost::aggregate(&request, &packages, &shares, &pkp).unwrap();

    // Signatures go onto the proved PCZT; extraction checks everything.
    let signed = zd_pczt::apply_signatures(proved, &sigs).unwrap();
    let tx = TransactionExtractor::new(signed)
        .extract(UnwrapErr(SysRng))
        .expect("valid transaction");
    assert!(tx.ironwood_bundle().is_some());
}

#[test]
fn single_signer_with_ask() {
    // HSM-style 1/1: ask generated outside any seed, account on the use_qsk path.
    let ask_scalar = {
        use zd_frost::Field;
        zd_frost::PallasScalarField::random(&mut OsRng)
    };
    let (ask_scalar, ak) = zd_keys::zip2005::normalize_ask(ask_scalar).unwrap();
    let ask = {
        use ff::PrimeField;
        orchard::primitives::redpallas::SigningKey::<orchard::primitives::redpallas::SpendAuth>::try_from(
            ask_scalar.to_repr(),
        )
        .unwrap()
    };
    let (account, _qsk) = zd_keys::AccountKeys::derive(&[7u8; 32], ak).unwrap();

    let pczt = build_pczt(account.fvk());
    let request = zd_pczt::signing_request(&pczt, &ak).unwrap();
    let sigs = zd_pczt::sign_with_ask(&request, &ask, &mut UnwrapErr(SysRng));
    let signed = zd_pczt::apply_signatures(pczt, &sigs).unwrap();
    let proved = zd_pczt::prove(signed, None, Some(ironwood_pk()), &mut UnwrapErr(SysRng)).unwrap();
    TransactionExtractor::new(proved)
        .extract(UnwrapErr(SysRng))
        .expect("valid transaction");
}
