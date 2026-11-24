//! Wallet state end to end: a real detector scans an in-memory chain into
//! the wallet's `WalletIngest` over gRPC, the commitment trees follow the
//! same chain and confirm the notes, and a `Wallet.Send` builds, proves
//! (prover service), signs (1/1 signer service), extracts and records the
//! spend.

use std::collections::HashMap;

use std::time::Duration;

use ff::PrimeField;
use incrementalmerkletree::frontier::Frontier;
use orchard::bundle::BundleVersion;
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::note::ExtractedNoteCommitment;
use orchard::value::NoteValue;
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use rand_core_06::OsRng;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};
use zcash_client_backend::proto::compact_formats as cf;
use zcash_protocol::consensus::{BlockHeight, NetworkType};
use zd_detect::Detector;
use zd_frost::Field;
use zd_proto::v1::{
    AccountRef, BalanceRequest, NoteReport, NullifierBatch, Pool, SendRequest,
    prover_client::ProverClient, prover_server::ProverServer, signer_client::SignerClient,
    signer_server::SignerServer, wallet_client::WalletClient,
    wallet_ingest_client::WalletIngestClient, wallet_ingest_server::WalletIngestServer,
    wallet_server::WalletServer,
};
use zd_services::{
    detector::{self, BlockSource, DetectorError},
    prover::{ProverService, ProvingKeys},
    signer::{AllowAll, SignerAccount, SingleSignerService},
};
use zd_wallet::{
    Error, WalletDb,
    ingest::Ingested,
    server::{FollowConfig, IngestService, WalletService, WalletState, follow_chain},
    tree::TreeTracker,
};

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

struct Acct {
    ufvk: String,
    fp: [u8; 32],
    fvk: FullViewingKey,
    ak: [u8; 32],
    ask: orchard::primitives::redpallas::SigningKey<orchard::primitives::redpallas::SpendAuth>,
}

fn account() -> Acct {
    let s = zd_frost::PallasScalarField::random(&mut OsRng);
    let (s, ak) = zd_keys::zip2005::normalize_ask(s).unwrap();
    let ask = orchard::primitives::redpallas::SigningKey::try_from(s.to_repr()).unwrap();
    let (keys, _qsk) = zd_keys::AccountKeys::derive(&[5u8; 32], ak).unwrap();
    let fvk = keys.fvk().clone();
    let ufvk = zd_address::keys::ufvk(&fvk, NetworkType::Test);
    Acct {
        fp: zd_address::keys::fingerprint(&ufvk),
        ufvk,
        fvk,
        ak,
        ask,
    }
}

fn account_ref(fp: &[u8; 32]) -> Option<AccountRef> {
    Some(AccountRef {
        ufvk_fingerprint: fp.to_vec(),
        network: 0,
    })
}

type Payments = Vec<(orchard::Address, u64)>;

fn bundle(version: BundleVersion, to: &Payments) -> Vec<cf::CompactOrchardAction> {
    if to.is_empty() {
        return vec![];
    }
    let mut b = orchard::builder::Builder::new(
        orchard::builder::BundleType::DEFAULT,
        version,
        version.default_flags(),
        orchard::Anchor::empty_tree(),
    )
    .unwrap();
    for (a, v) in to {
        b.add_output(None, *a, NoteValue::from_raw(*v), [0u8; 512])
            .unwrap();
    }
    let (bundle, _) = b.build::<i64>(&mut UnwrapErr(SysRng)).unwrap().unwrap();
    bundle
        .actions()
        .iter()
        .map(|a| cf::CompactOrchardAction {
            nullifier: a.nullifier().to_bytes().to_vec(),
            cmx: a.cmx().to_bytes().to_vec(),
            ephemeral_key: a.encrypted_note().epk_bytes.to_vec(),
            ciphertext: a.encrypted_note().enc_ciphertext.0[..52].to_vec(),
        })
        .collect()
}

fn block_hash(tag: u8, height: u64) -> Vec<u8> {
    let mut h = vec![tag; 32];
    h[..8].copy_from_slice(&height.to_le_bytes());
    h
}

/// A linked chain, one transaction per block, on top of `prev` with tree
/// sizes `sizes` (orchard, ironwood) at its start.
fn chain_on(
    start: u64,
    tag: u8,
    prev: Vec<u8>,
    sizes: (u32, u32),
    blocks: Vec<(Payments, Payments)>,
) -> Vec<cf::CompactBlock> {
    let (mut o, mut i) = sizes;
    let mut prev = prev;
    blocks
        .into_iter()
        .enumerate()
        .map(|(n, (op, ip))| {
            let orchard = bundle(BundleVersion::orchard_v2(), &op);
            let ironwood = bundle(BundleVersion::ironwood_v3(), &ip);
            o += orchard.len() as u32;
            i += ironwood.len() as u32;
            let height = start + n as u64;
            let hash = block_hash(tag, height);
            cf::CompactBlock {
                height,
                hash: hash.clone(),
                prev_hash: std::mem::replace(&mut prev, hash),
                vtx: vec![cf::CompactTx {
                    txid: vec![0x70 + n as u8; 32],
                    actions: orchard,
                    ironwood_actions: ironwood,
                    ..Default::default()
                }],
                chain_metadata: Some(cf::ChainMetadata {
                    sapling_commitment_tree_size: 0,
                    orchard_commitment_tree_size: o,
                    ironwood_commitment_tree_size: i,
                }),
                ..Default::default()
            }
        })
        .collect()
}

/// A chain from empty trees on top of block `start - 1` with hash GENESIS.
fn chain(start: u64, blocks: Vec<(Payments, Payments)>) -> Vec<cf::CompactBlock> {
    chain_on(start, 1, GENESIS.to_vec(), (0, 0), blocks)
}

const GENESIS: [u8; 32] = [0xee; 32];

struct Memory(Vec<cf::CompactBlock>);

#[tonic::async_trait]
impl BlockSource for Memory {
    async fn tip(&mut self) -> Result<u64, DetectorError> {
        Ok(self.0.last().unwrap().height)
    }
    async fn blocks(&mut self, from: u64, to: u64) -> Result<Vec<cf::CompactBlock>, DetectorError> {
        Ok(self
            .0
            .iter()
            .filter(|b| b.height >= from && b.height <= to)
            .cloned()
            .collect())
    }
}

async fn serve<S>(svc: S) -> Channel
where
    S: tower::Service<
            http::Request<tonic::body::Body>,
            Response = http::Response<tonic::body::Body>,
            Error = std::convert::Infallible,
        > + tonic::server::NamedService
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(
        Server::builder()
            .add_service(svc)
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap()
}

fn other_address() -> orchard::Address {
    FullViewingKey::from(&SpendingKey::from_bytes([9; 32]).unwrap())
        .address_at(0u32, Scope::External)
}

/// A note report for a note to `fvk` that is not on the chain.
fn forged_report(fp: &[u8; 32], fvk: &FullViewingKey, height: u32) -> NoteReport {
    let to = fvk.address_at(3u32, Scope::External);
    let v = BundleVersion::ironwood_v3();
    let mut b = orchard::builder::Builder::new(
        orchard::builder::BundleType::DEFAULT,
        v,
        v.default_flags(),
        orchard::Anchor::empty_tree(),
    )
    .unwrap();
    b.add_output(None, to, NoteValue::from_raw(9_000_000), [0u8; 512])
        .unwrap();
    let (bundle, meta) = b.build::<i64>(&mut UnwrapErr(SysRng)).unwrap().unwrap();
    let action = &bundle.actions()[meta.output_action_index(0).unwrap()];
    let domain = orchard::note_encryption::IronwoodDomain::for_action(action);
    let (note, _, _) = zcash_note_encryption::try_note_decryption(
        &domain,
        &fvk.to_ivk(Scope::External).prepare(),
        action,
    )
    .unwrap();
    NoteReport {
        account: account_ref(fp),
        height,
        block_hash: vec![3; 32],
        txid: vec![0x72; 32],
        pool: Pool::Ironwood as i32,
        action_index: 0,
        commitment_position: 4,
        cmx: ExtractedNoteCommitment::from(note.commitment())
            .to_bytes()
            .to_vec(),
        scope: zd_proto::v1::Scope::External as i32,
        recipient: note.recipient().to_raw_address_bytes().to_vec(),
        value_zat: note.value().inner(),
        rho: note.rho().to_bytes().to_vec(),
        rseed: note.rseed().as_bytes().to_vec(),
        note_version: 3,
        memo: vec![],
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn detect_confirm_and_send() {
    let acct = account();
    let ext = acct.fvk.address_at(1u32, Scope::External);
    let int = acct.fvk.address_at(0u32, Scope::Internal);
    let them = other_address();

    let db = WalletDb::in_memory().unwrap();
    assert_eq!(
        db.add_account(&acct.ufvk, None, "treasury", 10).unwrap(),
        acct.fp
    );

    // Heights 10..=14. Ironwood note at 10, Orchard change-like note at 11.
    let blocks = chain(
        10,
        vec![
            (vec![], vec![(ext, 600_000), (them, 1)]),
            (vec![(int, 50_000)], vec![]),
            (vec![], vec![(them, 2)]),
            (vec![], vec![]),
            (vec![], vec![]),
        ],
    );

    let trees = TreeTracker::new(
        9,
        Some(vec![0xee; 32]),
        Frontier::empty(),
        Frontier::empty(),
    )
    .unwrap();
    let state = WalletState::new(db, trees, network());
    let mut ingest =
        WalletIngestClient::new(serve(WalletIngestServer::new(IngestService(state.clone()))).await);

    // A detector with only the IVKs reports into wallet state.
    let det = Detector::new(
        account_ref(&acct.fp).unwrap(),
        &acct.fvk.to_ivk(Scope::External),
        &acct.fvk.to_ivk(Scope::Internal),
    );
    let mut source = Memory(blocks.clone());
    let summary = detector::scan_range(
        &mut source,
        std::slice::from_ref(&det),
        &mut ingest,
        10,
        14,
        Some(&GENESIS),
    )
    .await
    .unwrap();
    assert_eq!(summary.notes_ack.accepted, 2);
    assert_eq!(summary.notes_ack.rejected, 0);

    // Lies are refused; replays are duplicates.
    let mut lies = Vec::new();
    let honest = forged_report(&acct.fp, &acct.fvk, 12);
    let mut bumped = honest.clone();
    bumped.value_zat += 1;
    lies.push(bumped);
    let mut wrong_scope = honest.clone();
    wrong_scope.scope = zd_proto::v1::Scope::Internal as i32;
    lies.push(wrong_scope);
    let mut stranger = honest.clone();
    stranger.account = account_ref(&[7; 32]);
    lies.push(stranger);
    // Self-consistent but not on chain: accepted now, dropped by the tree.
    lies.push(honest.clone());
    let ack = ingest
        .report_notes(tokio_stream::iter(lies))
        .await
        .unwrap()
        .into_inner();
    assert_eq!((ack.accepted, ack.rejected), (1, 3));
    assert_eq!(
        state.db.lock().unwrap().ingest_note(&honest).unwrap(),
        Ingested::Duplicate
    );

    // Nothing is spendable until the trees confirm it.
    assert_eq!(state.db.lock().unwrap().balance(&acct.fp).unwrap(), (0, 0));
    let cfg = FollowConfig {
        confirmations: 0,
        poll: Duration::from_millis(1),
        ..Default::default()
    };
    follow_chain(&state, &mut Memory(blocks.clone()), cfg, Some(14))
        .await
        .unwrap();
    assert_eq!(state.trees.lock().unwrap().height(), 14);
    assert_eq!(
        state.db.lock().unwrap().balance(&acct.fp).unwrap(),
        (50_000, 600_000)
    );
    let forged_left: i64 = state
        .db
        .lock()
        .unwrap()
        .spendable_notes(&acct.fp)
        .unwrap()
        .iter()
        .filter(|n| n.note.value().inner() == 9_000_000)
        .count() as i64;
    assert_eq!(forged_left, 0, "the forged note was dropped");

    // Prover and 1/1 signer services.
    let prover = ProverClient::new(
        serve(ProverServer::new(ProverService::new(
            ProvingKeys::ironwood(),
            1,
        )))
        .await,
    );
    let mut signers = HashMap::new();
    signers.insert(
        acct.fp.to_vec(),
        SignerAccount {
            ak: acct.ak,
            ask: acct.ask.clone(),
        },
    );
    let signer = SignerClient::new(
        serve(SignerServer::new(SingleSignerService::new(
            signers, AllowAll,
        )))
        .await,
    );
    let mut wallet = WalletClient::new(
        serve(WalletServer::new(WalletService::new(
            state.clone(),
            prover,
            signer,
            None,
        )))
        .await,
    );

    let bal = wallet
        .get_balance(BalanceRequest {
            account: account_ref(&acct.fp),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (bal.orchard_zat, bal.ironwood_zat, bal.tree_height),
        (50_000, 600_000, 14)
    );

    // Too much.
    let err = wallet
        .send(SendRequest {
            account: account_ref(&acct.fp),
            recipient: hex::encode(them.to_raw_address_bytes()),
            amount_zat: 10_000_000,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    let sent = wallet
        .send(SendRequest {
            account: account_ref(&acct.fp),
            recipient: hex::encode(them.to_raw_address_bytes()),
            amount_zat: 100_000,
            memo: b"invoice 42".to_vec(),
            reason: "test payout".into(),
            broadcast: false,
        })
        .await
        .unwrap()
        .into_inner();
    // One Ironwood spend, recipient and change outputs: two logical actions.
    assert_eq!(sent.fee_zat, 10_000);
    assert_eq!(sent.txid.len(), 32);
    assert!(!sent.broadcast);
    let tx = zcash_primitives::transaction::Transaction::read(
        sent.raw_tx.as_slice(),
        zcash_protocol::consensus::BranchId::for_height(&network(), BlockHeight::from_u32(15)),
    )
    .unwrap();
    assert_eq!(tx.txid().as_ref().as_slice(), sent.txid.as_slice());

    // The Ironwood note is held for the pending transaction.
    assert_eq!(
        state.db.lock().unwrap().balance(&acct.fp).unwrap(),
        (50_000, 0)
    );

    // The spend is mined: its nullifier marks the note spent for good.
    let nf = {
        let db = state.db.lock().unwrap();
        db.conn_for_tests()
            .query_row(
                "SELECT nullifier FROM notes WHERE pending_txid = ?1",
                [&sent.txid],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .unwrap()
    };
    let batch = NullifierBatch {
        height: 15,
        block_hash: vec![15; 32],
        pool: Pool::Ironwood as i32,
        nullifiers: vec![vec![0; 32], nf],
    };
    assert_eq!(
        state.db.lock().unwrap().ingest_nullifiers(&batch).unwrap(),
        1
    );
    assert_eq!(
        state.db.lock().unwrap().clear_pending(&sent.txid).unwrap(),
        0
    );
    assert_eq!(
        state.db.lock().unwrap().balance(&acct.fp).unwrap(),
        (50_000, 0)
    );
}

#[test]
fn reorg_rewinds_trees_and_notes() {
    let acct = account();
    let ext = acct.fvk.address_at(1u32, Scope::External);
    let db = WalletDb::in_memory().unwrap();
    db.add_account(&acct.ufvk, None, "", 10).unwrap();

    let blocks = chain(
        10,
        vec![
            (vec![], vec![(ext, 1_000)]),
            (vec![], vec![(ext, 2_000)]),
            (vec![], vec![]),
        ],
    );
    let det = Detector::new(
        account_ref(&acct.fp).unwrap(),
        &acct.fvk.to_ivk(Scope::External),
        &acct.fvk.to_ivk(Scope::Internal),
    );
    let mut trees = TreeTracker::new(9, None, Frontier::empty(), Frontier::empty()).unwrap();
    for b in &blocks {
        let r = det.scan_block(&detector::from_lightwalletd(b).unwrap());
        for n in &r.notes {
            db.ingest_note(n).unwrap();
        }
        trees.apply_block(&db, b).unwrap();
    }
    assert_eq!(db.balance(&acct.fp).unwrap(), (0, 3_000));
    let anchor_at_10 = {
        let mut t = TreeTracker::new(9, None, Frontier::empty(), Frontier::empty()).unwrap();
        t.apply_block(&db, &blocks[0]).unwrap();
        t.anchor(orchard::ValuePool::Ironwood).unwrap()
    };

    // A block that does not extend 12 is a reorg.
    let fork = chain_on(13, 2, vec![0xab; 32], (0, 4), vec![(vec![], vec![])]);
    assert!(matches!(
        trees.apply_block(&db, &fork[0]),
        Err(Error::Reorg(12))
    ));

    trees.rewind(10).unwrap();
    db.rewind(10).unwrap();
    assert_eq!(db.reorg_marker().unwrap(), (1, 11));
    assert_eq!(trees.height(), 10);
    assert_eq!(trees.sizes(), (0, 2));
    assert_eq!(
        trees.anchor(orchard::ValuePool::Ironwood).unwrap(),
        anchor_at_10
    );
    assert_eq!(db.balance(&acct.fp).unwrap(), (0, 1_000));
    // A detector rescans block 11 and it applies again on top.
    let r = det.scan_block(&detector::from_lightwalletd(&blocks[1]).unwrap());
    for n in &r.notes {
        db.ingest_note(n).unwrap();
    }
    trees.apply_block(&db, &blocks[1]).unwrap();
    assert_eq!(db.balance(&acct.fp).unwrap(), (0, 3_000));
    // Our notes (not the bundles' padding actions) can be witnessed.
    let notes = db.spendable_notes(&acct.fp).unwrap();
    assert_eq!(notes.len(), 2);
    for n in notes {
        assert!(trees.witness(n.pool, n.position).is_ok());
    }
}

/// Wallet state hits a reorg, rewinds and bumps its epoch; the detector
/// finds the reorg itself, rescans the new chain, and reports a note for a
/// block the trees already applied. Wallet state replays the trees from
/// there, and the note becomes spendable.
#[tokio::test(flavor = "multi_thread")]
async fn wallet_and_detector_recover_from_reorg() {
    let acct = account();
    let ext = acct.fvk.address_at(1u32, Scope::External);
    let db = WalletDb::in_memory().unwrap();
    db.add_account(&acct.ufvk, None, "", 10).unwrap();

    let empty = || (vec![], vec![]);
    let a = chain(
        10,
        vec![
            empty(),
            empty(),
            (vec![], vec![(ext, 5_000)]),
            empty(),
            empty(),
        ],
    );
    let mut b = a[..2].to_vec();
    b.extend(chain_on(
        12,
        9,
        a[1].hash.clone(),
        (0, 0),
        vec![(vec![], vec![(ext, 7_000)]), empty(), empty(), empty()],
    ));

    let trees = TreeTracker::new(
        9,
        Some(GENESIS.to_vec()),
        Frontier::empty(),
        Frontier::empty(),
    )
    .unwrap();
    let state = WalletState::new(db, trees, network());
    let mut ingest =
        WalletIngestClient::new(serve(WalletIngestServer::new(IngestService(state.clone()))).await);
    let det = [Detector::new(
        account_ref(&acct.fp).unwrap(),
        &acct.fvk.to_ivk(Scope::External),
        &acct.fvk.to_ivk(Scope::Internal),
    )];
    let follow = FollowConfig {
        confirmations: 0,
        poll: Duration::from_millis(1),
        reorg_rewind: 3,
        ..Default::default()
    };
    let balance = |s: &WalletState<_>| s.db.lock().unwrap().balance(&acct.fp).unwrap().1;

    // Chain A: detected and confirmed.
    let s = detector::scan_range(
        &mut Memory(a.clone()),
        &det,
        &mut ingest,
        10,
        14,
        Some(&GENESIS),
    )
    .await
    .unwrap();
    assert_eq!((s.notes_ack.accepted, s.notes_ack.reorg_epoch), (1, 0));
    follow_chain(&state, &mut Memory(a.clone()), follow, Some(14))
        .await
        .unwrap();
    assert_eq!(balance(&state), 5_000);

    // Chain B wins. Wallet state sees 15 does not extend its 14, rewinds to
    // 11, forgets A's note, and applies B (whose note nobody reported yet).
    follow_chain(&state, &mut Memory(b.clone()), follow, Some(15))
        .await
        .unwrap();
    assert_eq!(state.trees.lock().unwrap().height(), 15);
    assert_eq!(balance(&state), 0);
    assert_eq!(state.db.lock().unwrap().reorg_marker().unwrap(), (1, 12));

    // The detector notices on its own: B's 15 does not extend A's 14.
    let err = detector::scan_range(
        &mut Memory(b.clone()),
        &det,
        &mut ingest,
        15,
        15,
        Some(&a[4].hash),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, DetectorError::Reorg { height: 15 }));
    // It steps back and rescans; wallet state's ack names the same point.
    let s = detector::scan_range(&mut Memory(b.clone()), &det, &mut ingest, 12, 15, None)
        .await
        .unwrap();
    assert_eq!(s.notes_ack.accepted, 1);
    assert_eq!((s.notes_ack.reorg_epoch, s.notes_ack.rescan_from), (1, 12));

    // The note's block was already applied, so wallet state rewound its
    // trees to 11; following again confirms the note.
    assert_eq!(state.trees.lock().unwrap().height(), 11);
    assert_eq!(balance(&state), 0);
    follow_chain(&state, &mut Memory(b.clone()), follow, Some(15))
        .await
        .unwrap();
    assert_eq!(balance(&state), 7_000);
}
