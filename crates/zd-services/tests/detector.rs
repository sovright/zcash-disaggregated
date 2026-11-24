//! Detector daemon against an in-memory block source and a real gRPC
//! WalletIngest server that records what it receives: multi-account scans,
//! chain-linkage reorgs, and rescans requested by wallet state.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use orchard::bundle::BundleVersion;
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::value::NoteValue;
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status, Streaming};
use zcash_client_backend::proto::compact_formats as cf;
use zd_detect::Detector;
use zd_proto::v1::{
    AccountRef, IngestAck, NoteReport, NullifierBatch, Pool,
    wallet_ingest_client::WalletIngestClient,
    wallet_ingest_server::{WalletIngest, WalletIngestServer},
};
use zd_services::detector::{self, BlockSource, Cursor, DetectorError, FollowConfig};

#[derive(Default, Clone)]
struct Recorder {
    notes: Arc<Mutex<Vec<NoteReport>>>,
    nullifiers: Arc<Mutex<Vec<NullifierBatch>>>,
    /// (reorg_epoch, rescan_from) to put in every ack.
    reorg: Arc<Mutex<(u64, u32)>>,
}

impl Recorder {
    fn ack(&self, accepted: u64) -> IngestAck {
        let (reorg_epoch, rescan_from) = *self.reorg.lock().unwrap();
        IngestAck {
            accepted,
            reorg_epoch,
            rescan_from,
            ..Default::default()
        }
    }
}

#[tonic::async_trait]
impl WalletIngest for Recorder {
    async fn report_notes(
        &self,
        request: Request<Streaming<NoteReport>>,
    ) -> Result<Response<IngestAck>, Status> {
        let mut s = request.into_inner();
        let mut n = 0;
        while let Some(r) = s.message().await? {
            self.notes.lock().unwrap().push(r);
            n += 1;
        }
        Ok(Response::new(self.ack(n)))
    }
    async fn report_nullifiers(
        &self,
        request: Request<Streaming<NullifierBatch>>,
    ) -> Result<Response<IngestAck>, Status> {
        let mut s = request.into_inner();
        let mut n = 0;
        while let Some(r) = s.message().await? {
            self.nullifiers.lock().unwrap().push(r);
            n += 1;
        }
        Ok(Response::new(self.ack(n)))
    }
}

async fn ingest(rec: Recorder) -> WalletIngestClient<Channel> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(
        Server::builder()
            .add_service(WalletIngestServer::new(rec))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    WalletIngestClient::new(
        Channel::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap(),
    )
}

fn actions(
    version: BundleVersion,
    to: &[(orchard::Address, u64)],
) -> Vec<cf::CompactOrchardAction> {
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

type Payments = Vec<(orchard::Address, u64)>;

fn hash(tag: u8, height: u64) -> Vec<u8> {
    let mut h = vec![tag; 32];
    h[..8].copy_from_slice(&height.to_le_bytes());
    h
}

/// A linked chain of blocks; each entry is (orchard payments, ironwood
/// payments). `tag` distinguishes forks; block `start - 1` has tag 0.
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
            let orchard = if op.is_empty() {
                vec![]
            } else {
                actions(BundleVersion::orchard_v2(), &op)
            };
            let ironwood = if ip.is_empty() {
                vec![]
            } else {
                actions(BundleVersion::ironwood_v3(), &ip)
            };
            o += orchard.len() as u32;
            i += ironwood.len() as u32;
            let height = start + n as u64;
            let h = hash(tag, height);
            cf::CompactBlock {
                height,
                hash: h.clone(),
                prev_hash: std::mem::replace(&mut prev, h),
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

fn chain(start: u64, blocks: Vec<(Payments, Payments)>) -> Vec<cf::CompactBlock> {
    chain_on(start, 1, hash(0, start - 1), (100, 10), blocks)
}

/// Serves `blocks`, plus a parent block below the first; switches to
/// `after` once `switch_after` block requests have been served (at the next
/// tip query); stops after
/// `max_tips` tip queries.
struct Memory {
    blocks: Vec<cf::CompactBlock>,
    after: Option<Vec<cf::CompactBlock>>,
    switch_after: u32,
    requests: u32,
    tip_calls: u32,
    max_tips: u32,
}

impl Memory {
    fn new(blocks: Vec<cf::CompactBlock>, max_tips: u32) -> Self {
        Memory {
            blocks,
            after: None,
            switch_after: 0,
            requests: 0,
            tip_calls: 0,
            max_tips,
        }
    }
}

#[tonic::async_trait]
impl BlockSource for Memory {
    async fn tip(&mut self) -> Result<u64, DetectorError> {
        self.tip_calls += 1;
        if self.tip_calls > self.max_tips {
            return Err(DetectorError::Source("stop".into()));
        }
        if self.requests >= self.switch_after
            && let Some(after) = self.after.take()
        {
            self.blocks = after;
        }
        Ok(self.blocks.last().unwrap().height)
    }
    async fn blocks(&mut self, from: u64, to: u64) -> Result<Vec<cf::CompactBlock>, DetectorError> {
        self.requests += 1;
        let first = self.blocks[0].height;
        let mut out = Vec::new();
        if from < first {
            // The parent of the first block, so callers can learn its hash.
            out.push(cf::CompactBlock {
                height: first - 1,
                hash: self.blocks[0].prev_hash.clone(),
                ..Default::default()
            });
        }
        out.extend(
            self.blocks
                .iter()
                .filter(|b| b.height >= from && b.height <= to)
                .cloned(),
        );
        Ok(out)
    }
}

fn fvk(seed: u8) -> FullViewingKey {
    FullViewingKey::from(&SpendingKey::from_bytes([seed; 32]).unwrap())
}

fn detector_for(fvk: &FullViewingKey, tag: u8) -> Detector {
    Detector::new(
        AccountRef {
            ufvk_fingerprint: vec![tag; 32],
            network: 0,
        },
        &fvk.to_ivk(Scope::External),
        &fvk.to_ivk(Scope::Internal),
    )
}

fn cfg(batch: u64) -> FollowConfig {
    FollowConfig {
        batch,
        poll: Duration::from_millis(1),
        reorg_rewind: 2,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn detector_follows_chain_and_reports() {
    let me = fvk(1);
    let other = fvk(2);
    let ext = me.address_at(9u32, Scope::External);
    let int = me.address_at(0u32, Scope::Internal);
    let them = other.address_at(0u32, Scope::External);

    let blocks = chain(
        3_500_000,
        vec![
            (vec![(ext, 1)], vec![]),
            (vec![], vec![(ext, 2), (them, 3)]),
            (vec![], vec![]),
            (vec![(them, 4)], vec![(int, 5)]),
        ],
    );
    let mut source = Memory::new(blocks.clone(), 2);
    // One process, two accounts.
    let dets = [detector_for(&me, 1), detector_for(&other, 2)];
    let rec = Recorder::default();
    let mut client = ingest(rec.clone()).await;

    // Batches of 3: two batches, then the source stops.
    let mut checkpoints = Vec::new();
    let err = detector::follow(
        &mut source,
        &dets,
        &mut client,
        Cursor::starting_at(3_500_000),
        cfg(3),
        |c| checkpoints.push(c.next),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, DetectorError::Source(ref m) if m == "stop"));
    assert_eq!(checkpoints, vec![3_500_003, 3_500_004]);

    let notes = rec.notes.lock().unwrap().clone();
    let mut mine: Vec<u64> = notes
        .iter()
        .filter(|n| n.account.as_ref().unwrap().ufvk_fingerprint == vec![1; 32])
        .map(|n| n.value_zat)
        .collect();
    mine.sort();
    assert_eq!(mine, vec![1, 2, 5]);
    let mut theirs: Vec<u64> = notes
        .iter()
        .filter(|n| n.account.as_ref().unwrap().ufvk_fingerprint == vec![2; 32])
        .map(|n| n.value_zat)
        .collect();
    theirs.sort();
    assert_eq!(theirs, vec![3, 4]);

    // Positions: tree sizes in lightwalletd are end-of-block, so the
    // detector must subtract the block's own actions.
    for n in &notes {
        let b = &blocks[(n.height - 3_500_000) as usize];
        let meta = b.chain_metadata.as_ref().unwrap();
        let (end, count) = if n.pool == Pool::Orchard as i32 {
            (meta.orchard_commitment_tree_size, b.vtx[0].actions.len())
        } else {
            (
                meta.ironwood_commitment_tree_size,
                b.vtx[0].ironwood_actions.len(),
            )
        };
        assert_eq!(
            n.commitment_position,
            u64::from(end) - count as u64 + u64::from(n.action_index)
        );
        assert_eq!(n.block_hash, b.hash);
        assert_eq!(n.txid, b.vtx[0].txid);
    }

    // Every block's nullifiers were forwarded once, not once per account
    // (3 blocks have actions; block 4 has both pools).
    let nfs = rec.nullifiers.lock().unwrap().clone();
    assert_eq!(nfs.len(), 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn detector_rescans_after_reorg() {
    let me = fvk(1);
    let ext = me.address_at(0u32, Scope::External);
    // Chain A: 100..=104 with a note at 103. Chain B forks after 101 and has
    // a different note at 103.
    let a = chain(
        100,
        vec![
            (vec![], vec![]),
            (vec![], vec![]),
            (vec![], vec![]),
            (vec![], vec![(ext, 1_000)]),
            (vec![], vec![]),
        ],
    );
    let mut b = a[..2].to_vec();
    b.extend(chain_on(
        102,
        2,
        a[1].hash.clone(),
        (100, 10),
        vec![
            (vec![], vec![]),
            (vec![], vec![(ext, 2_000)]),
            (vec![], vec![]),
            (vec![], vec![]),
        ],
    ));

    // Batch 1 (100..=104) is served from A; then the source switches to B.
    let mut source = Memory::new(a, 4);
    source.after = Some(b);
    source.switch_after = 1;
    let rec = Recorder::default();
    let mut client = ingest(rec.clone()).await;
    let mut cursors = Vec::new();
    detector::follow(
        &mut source,
        &[detector_for(&me, 1)],
        &mut client,
        Cursor::starting_at(100),
        cfg(10),
        |c| cursors.push(c.clone()),
    )
    .await
    .unwrap_err();

    // A scanned to 104; 105 did not link (its parent is B's 104), so the
    // detector stepped back 2 and rescanned B from 103.
    let nexts: Vec<u64> = cursors.iter().map(|c| c.next).collect();
    assert_eq!(nexts, vec![105, 103, 106]);
    assert_eq!(cursors[1].prev_hash, None);
    assert_eq!(cursors[2].prev_hash, Some(hash(2, 105)));
    let values: Vec<(u32, u64, Vec<u8>)> = rec
        .notes
        .lock()
        .unwrap()
        .iter()
        .map(|n| (n.height, n.value_zat, n.block_hash.clone()))
        .collect();
    assert_eq!(
        values,
        vec![(103, 1_000, hash(1, 103)), (103, 2_000, hash(2, 103))]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn wallet_reorg_epoch_sends_detector_back() {
    let me = fvk(1);
    let ext = me.address_at(0u32, Scope::External);
    let blocks = chain(
        200,
        vec![(vec![], vec![(ext, 7)]), (vec![], vec![]), (vec![], vec![])],
    );
    let rec = Recorder::default();
    // Wallet state has already been through one reorg before this detector
    // started: a new detector adopts the epoch without going back.
    *rec.reorg.lock().unwrap() = (1, 150);
    let mut client = ingest(rec.clone()).await;
    let dets = [detector_for(&me, 1)];
    let mut source = Memory::new(blocks.clone(), 1);
    let mut cursors = Vec::new();
    detector::follow(
        &mut source,
        &dets,
        &mut client,
        Cursor::starting_at(200),
        cfg(10),
        |c| cursors.push(c.clone()),
    )
    .await
    .unwrap_err();
    assert_eq!(cursors.last().unwrap().next, 203);
    assert_eq!(cursors.last().unwrap().reorg_epoch, Some(1));

    // Now wallet state rewinds past a reorg and wants everything from 201.
    *rec.reorg.lock().unwrap() = (2, 201);
    let mut cursor = cursors.last().unwrap().clone();
    let mut source = Memory::new(
        chain(
            200,
            vec![
                (vec![], vec![(ext, 7)]),
                (vec![], vec![]),
                (vec![], vec![]),
                (vec![], vec![]),
            ],
        ),
        2,
    );
    let mut nexts = Vec::new();
    detector::follow(
        &mut source,
        &dets,
        &mut client,
        cursor.clone(),
        cfg(10),
        |c| {
            nexts.push(c.next);
            cursor = c.clone();
        },
    )
    .await
    .unwrap_err();
    // Scanned 203, was told to go back to 201, rescanned 201..=203.
    assert_eq!(nexts, vec![201, 204]);
    assert_eq!(cursor.reorg_epoch, Some(2));

    // Unit checks of the ack rule.
    let ack = |epoch, from| IngestAck {
        reorg_epoch: epoch,
        rescan_from: from,
        ..Default::default()
    };
    let mut c = Cursor {
        next: 500,
        prev_hash: Some(vec![1]),
        reorg_epoch: Some(3),
    };
    assert!(!c.apply_ack(&ack(3, 100)), "same epoch: nothing to do");
    assert!(!c.apply_ack(&ack(4, 600)), "rescan point not reached yet");
    assert_eq!((c.next, c.reorg_epoch), (500, Some(4)));
    assert!(c.apply_ack(&ack(5, 450)));
    assert_eq!(
        (c.next, c.prev_hash.clone(), c.reorg_epoch),
        (450, None, Some(5))
    );
}

#[test]
fn rejects_inconsistent_tree_size() {
    let me = fvk(3);
    let mut b = chain(
        1,
        vec![(vec![], vec![(me.address_at(0u32, Scope::External), 1)])],
    )
    .remove(0);
    b.chain_metadata
        .as_mut()
        .unwrap()
        .ironwood_commitment_tree_size = 0;
    assert!(matches!(
        detector::from_lightwalletd(&b),
        Err(DetectorError::BadBlock { .. })
    ));
}
