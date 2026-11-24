use orchard::bundle::BundleVersion;
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::value::NoteValue;
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use zd_detect::{CompactActionBytes, CompactBlock, CompactTx, Detector, MalformedAction};
use zd_proto::v1::{AccountRef, Pool, Scope as PScope};

fn fvk(seed: u8) -> FullViewingKey {
    FullViewingKey::from(&SpendingKey::from_bytes([seed; 32]).unwrap())
}

fn detector(fvk: &FullViewingKey) -> Detector {
    Detector::new(
        AccountRef::default(),
        &fvk.to_ivk(Scope::External),
        &fvk.to_ivk(Scope::Internal),
    )
}

/// A bundle in `version` paying each (address, value), plus the output action
/// index of each payment.
fn bundle(
    version: BundleVersion,
    payments: &[(orchard::Address, u64)],
) -> (Vec<CompactActionBytes>, Vec<usize>) {
    let mut rng = UnwrapErr(SysRng);
    let mut b = orchard::builder::Builder::new(
        orchard::builder::BundleType::DEFAULT,
        version,
        version.default_flags(),
        orchard::Anchor::empty_tree(),
    )
    .unwrap();
    for (addr, v) in payments {
        b.add_output(None, *addr, NoteValue::from_raw(*v), [0u8; 512])
            .unwrap();
    }
    let (bundle, meta) = b.build::<i64>(&mut rng).unwrap().unwrap();
    let actions = bundle
        .actions()
        .iter()
        .map(|a| CompactActionBytes {
            nullifier: a.nullifier().to_bytes(),
            cmx: a.cmx().to_bytes(),
            ephemeral_key: a.encrypted_note().epk_bytes,
            ciphertext: a.encrypted_note().enc_ciphertext.0[..52]
                .try_into()
                .unwrap(),
        })
        .collect();
    let idx = (0..payments.len())
        .map(|i| meta.output_action_index(i).unwrap())
        .collect();
    (actions, idx)
}

#[test]
fn finds_own_notes_in_both_pools_with_positions() {
    let me = fvk(1);
    let stranger = fvk(2);
    let ext = me.address_at(5u32, Scope::External);
    let int = me.address_at(0u32, Scope::Internal);
    let other = stranger.address_at(0u32, Scope::External);

    let (iw, iw_idx) = bundle(
        BundleVersion::ironwood_v3(),
        &[(ext, 100), (int, 200), (other, 300)],
    );
    let (or, or_idx) = bundle(BundleVersion::orchard_v2(), &[(ext, 400)]);

    let block = CompactBlock {
        height: 3_500_000,
        hash: vec![0xab; 32],
        orchard_tree_size: 1_000,
        ironwood_tree_size: 50,
        txs: vec![
            CompactTx {
                txid: vec![1; 32],
                orchard: or.clone(),
                ironwood: vec![],
            },
            CompactTx {
                txid: vec![2; 32],
                orchard: vec![],
                ironwood: iw.clone(),
            },
        ],
    };

    let report = detector(&me).scan_block(&block);
    assert_eq!(report.notes.len(), 3);

    let find = |pool: Pool, v: u64| {
        report
            .notes
            .iter()
            .find(|n| n.pool == pool as i32 && n.value_zat == v)
            .unwrap()
    };
    let n = find(Pool::Ironwood, 100);
    assert_eq!(n.scope, PScope::External as i32);
    assert_eq!(n.note_version, 3);
    assert_eq!(n.txid, vec![2; 32]);
    assert_eq!(n.action_index as usize, iw_idx[0]);
    assert_eq!(n.commitment_position, 50 + iw_idx[0] as u64);
    assert_eq!(n.recipient, ext.to_raw_address_bytes().to_vec());
    assert_eq!(n.cmx, iw[iw_idx[0]].cmx.to_vec());

    let n = find(Pool::Ironwood, 200);
    assert_eq!(n.scope, PScope::Internal as i32);

    let n = find(Pool::Orchard, 400);
    assert_eq!(n.note_version, 2);
    assert_eq!(n.commitment_position, 1_000 + or_idx[0] as u64);
    assert_eq!(n.height, 3_500_000);

    // Every nullifier is forwarded, per pool.
    assert_eq!(report.nullifiers.len(), 2);
    let iw_nfs = report
        .nullifiers
        .iter()
        .find(|b| b.pool == Pool::Ironwood as i32)
        .unwrap();
    assert_eq!(iw_nfs.nullifiers.len(), iw.len());

    // The stranger only finds their own note.
    let theirs = detector(&stranger).scan_block(&block);
    assert_eq!(theirs.notes.len(), 1);
    assert_eq!(theirs.notes[0].value_zat, 300);
}

#[test]
fn ironwood_note_is_not_found_with_orchard_domain() {
    let me = fvk(3);
    let (iw, idx) = bundle(
        BundleVersion::ironwood_v3(),
        &[(me.address_at(0u32, Scope::External), 1)],
    );
    let d = detector(&me);
    assert!(
        d.try_action(orchard::ValuePool::Ironwood, &iw[idx[0]])
            .unwrap()
            .is_some()
    );
    assert!(
        d.try_action(orchard::ValuePool::Orchard, &iw[idx[0]])
            .unwrap()
            .is_none()
    );
}

#[test]
fn malformed_action() {
    let d = detector(&fvk(4));
    let bad = CompactActionBytes {
        nullifier: [0xff; 32],
        cmx: [0; 32],
        ephemeral_key: [0; 32],
        ciphertext: [0; 52],
    };
    assert_eq!(
        d.try_action(orchard::ValuePool::Ironwood, &bad),
        Err(MalformedAction::Nullifier)
    );
}
