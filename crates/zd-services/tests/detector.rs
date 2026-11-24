//! Detector daemon against an in-memory block source and a real gRPC
//! WalletIngest server that records what it receives.

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
use zd_services::detector::{self, BlockSource, DetectorError};

#[derive(Default, Clone)]
struct Recorder {
    notes: Arc<Mutex<Vec<NoteReport>>>,
    nullifiers: Arc<Mutex<Vec<NullifierBatch>>>,
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
        Ok(Response::new(IngestAck {
            accepted: n,
            ..Default::default()
        }))
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
        Ok(Response::new(IngestAck {
            accepted: n,
            ..Default::default()
        }))
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

/// Builds a chain of blocks; each entry is (orchard payments, ironwood payments).
fn chain(start: u64, blocks: Vec<(Payments, Payments)>) -> Vec<cf::CompactBlock> {
    let (mut o, mut i) = (100u32, 10u32);
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
            cf::CompactBlock {
                height: start + n as u64,
                hash: vec![n as u8; 32],
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

struct Memory {
    blocks: Vec<cf::CompactBlock>,
    tip_calls: u32,
}

#[tonic::async_trait]
impl BlockSource for Memory {
    async fn tip(&mut self) -> Result<u64, DetectorError> {
        self.tip_calls += 1;
        if self.tip_calls > 2 {
            return Err(DetectorError::Source("stop".into()));
        }
        Ok(self.blocks.last().unwrap().height)
    }
    async fn blocks(&mut self, from: u64, to: u64) -> Result<Vec<cf::CompactBlock>, DetectorError> {
        Ok(self
            .blocks
            .iter()
            .filter(|b| b.height >= from && b.height <= to)
            .cloned()
            .collect())
    }
}

fn fvk(seed: u8) -> FullViewingKey {
    FullViewingKey::from(&SpendingKey::from_bytes([seed; 32]).unwrap())
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
    let mut source = Memory {
        blocks: blocks.clone(),
        tip_calls: 0,
    };
    let det = Detector::new(
        AccountRef::default(),
        &me.to_ivk(Scope::External),
        &me.to_ivk(Scope::Internal),
    );
    let rec = Recorder::default();
    let mut client = ingest(rec.clone()).await;

    // Batches of 3: two batches, then the source stops.
    let mut checkpoints = Vec::new();
    let err = detector::follow(
        &mut source,
        &det,
        &mut client,
        3_500_000,
        3,
        Duration::from_millis(1),
        |h| checkpoints.push(h),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, DetectorError::Source(ref m) if m == "stop"));
    assert_eq!(checkpoints, vec![3_500_003, 3_500_004]);

    let notes = rec.notes.lock().unwrap().clone();
    let mut values: Vec<u64> = notes.iter().map(|n| n.value_zat).collect();
    values.sort();
    assert_eq!(values, vec![1, 2, 5]);

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

    // Every block's nullifiers were forwarded (3 blocks have actions; block
    // 4 has both pools).
    let nfs = rec.nullifiers.lock().unwrap().clone();
    assert_eq!(nfs.len(), 4);
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
