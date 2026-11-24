//! Wallet state's gRPC services and its chain follower.
//!
//! - [`IngestService`] implements `WalletIngest` for detectors.
//! - [`WalletService`] implements the operator `Wallet` API (balance, send).
//! - [`follow_chain`] keeps the commitment trees a few blocks behind the tip.
//!
//! The ingest API trusts nothing a detector says that it can check (see
//! [`crate::ingest`]), but it does not authenticate detectors either: run it
//! behind mTLS, so that an outsider cannot fill the database with junk.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU32, Ordering},
};
use std::time::Duration;

use tonic::{Request, Response, Status, Streaming, transport::Channel};
use zcash_client_backend::proto::service::{
    RawTransaction, compact_tx_streamer_client::CompactTxStreamerClient,
};
use zcash_protocol::{consensus::Parameters, memo::MemoBytes};
use zd_proto::v1::{
    Balance, BalanceRequest, IngestAck, NoteReport, NullifierBatch, SendRequest, SendResponse,
    prover_client::ProverClient, signer_client::SignerClient, wallet_ingest_server::WalletIngest,
    wallet_server::Wallet,
};
use zd_services::detector::BlockSource;

use crate::{
    Error, WalletDb,
    ingest::Ingested,
    send::{self, Payment},
    tree::TreeTracker,
};

/// Shared wallet state behind the services.
pub struct WalletState<P> {
    /// The database.
    pub db: Mutex<WalletDb>,
    /// The commitment trees.
    pub trees: Mutex<TreeTracker>,
    /// Consensus parameters.
    pub params: P,
    /// Last chain tip seen.
    pub tip: AtomicU32,
}

impl<P> WalletState<P> {
    /// Wraps a database and trees.
    pub fn new(db: WalletDb, trees: TreeTracker, params: P) -> Arc<Self> {
        let tip = trees.height();
        Arc::new(WalletState {
            db: Mutex::new(db),
            trees: Mutex::new(trees),
            params,
            tip: AtomicU32::new(tip),
        })
    }

    /// Replaces the trees (after a rebuild) and marks every note
    /// unconfirmed until the new trees confirm it again.
    pub fn reset_trees(&self, trees: TreeTracker) -> Result<(), Error> {
        let db = self.db.lock().expect("db lock");
        let mut t = self.trees.lock().expect("trees lock");
        db.mark_all_unconfirmed()?;
        *t = trees;
        Ok(())
    }

    fn tree_height(&self) -> u32 {
        self.trees.lock().expect("trees lock").height()
    }
}

fn status(e: Error) -> Status {
    match e {
        Error::UnknownAccount => Status::not_found("unknown account"),
        Error::Rejected(r) => Status::invalid_argument(r),
        Error::InsufficientFunds { .. } => Status::failed_precondition(e.to_string()),
        Error::Remote { .. } => Status::aborted(e.to_string()),
        e => Status::internal(e.to_string()),
    }
}

/// `WalletIngest` for detectors.
pub struct IngestService<P>(pub Arc<WalletState<P>>);

#[tonic::async_trait]
impl<P: Send + Sync + 'static> WalletIngest for IngestService<P> {
    async fn report_notes(
        &self,
        request: Request<Streaming<NoteReport>>,
    ) -> Result<Response<IngestAck>, Status> {
        let mut stream = request.into_inner();
        let mut ack = IngestAck::default();
        while let Some(r) = stream.message().await? {
            let outcome = self.0.db.lock().expect("db lock").ingest_note(&r);
            match outcome {
                Ok(Ingested::New) => ack.accepted += 1,
                Ok(Ingested::Duplicate) => ack.duplicates += 1,
                Err(Error::Rejected(reason)) | Err(Error::Tree(reason)) => {
                    tracing::warn!(height = r.height, %reason, "rejected note report");
                    ack.rejected += 1;
                }
                Err(Error::UnknownAccount) => ack.rejected += 1,
                Err(e) => return Err(status(e)),
            }
        }
        ack.tip_height = self.0.tree_height();
        Ok(Response::new(ack))
    }

    async fn report_nullifiers(
        &self,
        request: Request<Streaming<NullifierBatch>>,
    ) -> Result<Response<IngestAck>, Status> {
        let mut stream = request.into_inner();
        let mut ack = IngestAck::default();
        while let Some(b) = stream.message().await? {
            match self.0.db.lock().expect("db lock").ingest_nullifiers(&b) {
                Ok(_) => ack.accepted += 1,
                Err(Error::Rejected(_)) => ack.rejected += 1,
                Err(e) => return Err(status(e)),
            }
        }
        ack.tip_height = self.0.tree_height();
        Ok(Response::new(ack))
    }
}

/// The operator `Wallet` API.
pub struct WalletService<P> {
    state: Arc<WalletState<P>>,
    prover: ProverClient<Channel>,
    signer: SignerClient<Channel>,
    lightwalletd: Option<CompactTxStreamerClient<Channel>>,
}

impl<P> WalletService<P> {
    /// A service that proves with `prover`, signs with `signer`, and
    /// broadcasts through `lightwalletd` when asked to.
    pub fn new(
        state: Arc<WalletState<P>>,
        prover: ProverClient<Channel>,
        signer: SignerClient<Channel>,
        lightwalletd: Option<CompactTxStreamerClient<Channel>>,
    ) -> Self {
        WalletService {
            state,
            prover,
            signer,
            lightwalletd,
        }
    }
}

fn fingerprint(r: Option<&zd_proto::v1::AccountRef>) -> Result<[u8; 32], Status> {
    r.and_then(|a| a.ufvk_fingerprint.as_slice().try_into().ok())
        .ok_or_else(|| Status::invalid_argument("account fingerprint must be 32 bytes"))
}

#[tonic::async_trait]
impl<P: Parameters + Clone + Send + Sync + 'static> Wallet for WalletService<P> {
    async fn get_balance(
        &self,
        request: Request<BalanceRequest>,
    ) -> Result<Response<Balance>, Status> {
        let fp = fingerprint(request.get_ref().account.as_ref())?;
        let db = self.state.db.lock().expect("db lock");
        db.account(&fp).map_err(status)?;
        let (orchard_zat, ironwood_zat) = db.balance(&fp).map_err(status)?;
        drop(db);
        Ok(Response::new(Balance {
            orchard_zat,
            ironwood_zat,
            tree_height: self.state.tree_height(),
        }))
    }

    async fn send(&self, request: Request<SendRequest>) -> Result<Response<SendResponse>, Status> {
        let req = request.into_inner();
        let fp = fingerprint(req.account.as_ref())?;
        let recipient = zd_address::keys::parse_orchard_address(&req.recipient)
            .ok_or_else(|| Status::invalid_argument("recipient has no Orchard receiver"))?;
        let memo = if req.memo.is_empty() {
            MemoBytes::empty()
        } else {
            MemoBytes::from_bytes(&req.memo)
                .map_err(|_| Status::invalid_argument("memo is over 512 bytes"))?
        };
        let payment = Payment {
            recipient,
            amount: req.amount_zat,
            memo,
        };

        // Build and hold the notes under a job id, atomically with selection.
        let mut job_id = [0u8; 16];
        rand::fill(&mut job_id);
        let proposal = {
            let db = self.state.db.lock().expect("db lock");
            let trees = self.state.trees.lock().expect("trees lock");
            let target = self.state.tip.load(Ordering::Relaxed).max(trees.height()) + 1;
            let p = send::propose(&db, &trees, &self.state.params, target, &fp, &payment)
                .map_err(status)?;
            db.mark_pending(&p.note_ids, &job_id).map_err(status)?;
            p
        };
        let release = |e: Error| {
            let _ = self
                .state
                .db
                .lock()
                .expect("db lock")
                .clear_pending(&job_id);
            status(e)
        };

        let account = req.account.clone().unwrap_or_default();
        let (mut prover, mut signer) = (self.prover.clone(), self.signer.clone());
        let pczt = send::authorize(
            proposal.pczt,
            account,
            job_id.to_vec(),
            req.reason,
            &mut prover,
            &mut signer,
        )
        .await
        .map_err(release)?;
        let (tx, raw) = send::extract(pczt).map_err(release)?;
        let txid = tx.txid().as_ref().to_vec();
        self.state
            .db
            .lock()
            .expect("db lock")
            .rename_pending(&job_id, &txid)
            .map_err(status)?;

        let mut broadcast = false;
        if req.broadcast {
            let mut lwd = self
                .lightwalletd
                .clone()
                .ok_or_else(|| Status::failed_precondition("no lightwalletd configured"))?;
            let r = lwd
                .send_transaction(RawTransaction {
                    data: raw.clone(),
                    height: 0,
                })
                .await?
                .into_inner();
            if r.error_code != 0 {
                return Err(Status::aborted(format!(
                    "broadcast failed ({}): {}; notes stay held under the txid",
                    r.error_code, r.error_message
                )));
            }
            broadcast = true;
        }
        Ok(Response::new(SendResponse {
            txid,
            raw_tx: raw,
            fee_zat: proposal.fee,
            broadcast,
        }))
    }
}

/// How far behind the tip the trees stay, and how they poll.
#[derive(Clone, Copy, Debug)]
pub struct FollowConfig {
    /// Blocks to stay behind the tip, so detectors have reported a block
    /// before its notes are marked.
    pub confirmations: u32,
    /// Blocks per fetch.
    pub batch: u32,
    /// Poll interval at the tip.
    pub poll: Duration,
    /// Blocks to rewind on a reorg.
    pub reorg_rewind: u32,
}

impl Default for FollowConfig {
    fn default() -> Self {
        FollowConfig {
            confirmations: 3,
            batch: 100,
            poll: Duration::from_secs(15),
            reorg_rewind: 10,
        }
    }
}

/// Applies blocks to the trees until `stop_at` (if given) or forever.
///
/// On a reorg, rewinds the trees and the database by `reorg_rewind` blocks.
/// Notes in the discarded blocks are forgotten; detectors must rescan from
/// the logged height.
pub async fn follow_chain<P, S: BlockSource>(
    state: &WalletState<P>,
    source: &mut S,
    cfg: FollowConfig,
    stop_at: Option<u32>,
) -> Result<(), Error> {
    let src = |e: zd_services::detector::DetectorError| Error::Tree(e.to_string());
    loop {
        let tip = u32::try_from(source.tip().await.map_err(src)?)
            .map_err(|_| Error::Tree("tip height out of range".into()))?;
        state.tip.store(tip, Ordering::Relaxed);
        let next = state.tree_height() + 1;
        let target = tip.saturating_sub(cfg.confirmations);
        if let Some(stop) = stop_at
            && next > stop
        {
            return Ok(());
        }
        if target < next {
            tokio::time::sleep(cfg.poll).await;
            continue;
        }
        let mut to = target.min(next + cfg.batch.max(1) - 1);
        if let Some(stop) = stop_at {
            to = to.min(stop);
        }
        let blocks = source
            .blocks(u64::from(next), u64::from(to))
            .await
            .map_err(src)?;
        let db = state.db.lock().expect("db lock");
        let mut trees = state.trees.lock().expect("trees lock");
        for b in &blocks {
            match trees.apply_block(&db, b) {
                Ok(()) => {}
                Err(Error::Reorg(h)) => {
                    let back = (h as u32).saturating_sub(cfg.reorg_rewind);
                    tracing::warn!(at = h, rewind_to = back, "reorg; detectors must rescan");
                    trees.rewind(back)?;
                    db.rewind(u64::from(back))?;
                    break;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// Fresh trees for every account, from lightwalletd's tree state just before
/// the earliest account birthday. [`follow_chain`] then re-applies blocks
/// from there, re-confirming every stored note; until it catches up, notes
/// are not spendable. Use [`WalletState::reset_trees`] to swap them in.
pub async fn fresh_trees(
    earliest_birthday: u64,
    lightwalletd: &mut CompactTxStreamerClient<Channel>,
) -> Result<TreeTracker, Error> {
    let birthday = earliest_birthday;
    let ts = lightwalletd
        .get_tree_state(zcash_client_backend::proto::service::BlockId {
            height: birthday.saturating_sub(1),
            hash: vec![],
        })
        .await
        .map_err(|e| Error::Tree(e.message().to_string()))?
        .into_inner();
    TreeTracker::from_tree_state(&ts)
}
