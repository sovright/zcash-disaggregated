//! The detector daemon: compact blocks in (from lightwalletd), note and
//! nullifier reports out (to wallet state's `WalletIngest`).
//!
//! The detector is stateless apart from the next height to scan, which the
//! caller persists. It does not handle reorgs itself: every report carries
//! its block hash, and wallet state discards reports for blocks that leave
//! the best chain and asks detectors to rescan from the fork point.

use std::time::Duration;

use tonic::transport::Channel;
use zcash_client_backend::proto::{
    compact_formats as cf,
    service::{
        BlockId, BlockRange, ChainSpec, PoolType,
        compact_tx_streamer_client::CompactTxStreamerClient,
    },
};
use zd_detect::{BlockReport, CompactActionBytes, Detector};
use zd_proto::v1::{IngestAck, wallet_ingest_client::WalletIngestClient};

/// Detector errors.
#[derive(Debug, thiserror::Error)]
pub enum DetectorError {
    /// lightwalletd returned an error or broke the stream.
    #[error("lightwalletd: {0}")]
    Source(String),
    /// A compact block is inconsistent (bad field lengths or tree sizes).
    #[error("block {height}: {reason}")]
    BadBlock {
        /// Height of the bad block.
        height: u64,
        /// What was wrong.
        reason: String,
    },
    /// Wallet state refused or failed.
    #[error("wallet ingest: {0}")]
    Ingest(String),
}

fn action(height: u64, a: &cf::CompactOrchardAction) -> Result<CompactActionBytes, DetectorError> {
    let bad = |what: &str| DetectorError::BadBlock {
        height,
        reason: format!("action {what} has the wrong length"),
    };
    Ok(CompactActionBytes {
        nullifier: a
            .nullifier
            .as_slice()
            .try_into()
            .map_err(|_| bad("nullifier"))?,
        cmx: a.cmx.as_slice().try_into().map_err(|_| bad("cmx"))?,
        ephemeral_key: a
            .ephemeral_key
            .as_slice()
            .try_into()
            .map_err(|_| bad("ephemeral key"))?,
        ciphertext: a
            .ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| bad("ciphertext"))?,
    })
}

/// Converts a lightwalletd compact block. lightwalletd reports each tree's
/// size at the *end* of the block; the detector needs the size before it.
pub fn from_lightwalletd(
    block: &cf::CompactBlock,
) -> Result<zd_detect::CompactBlock, DetectorError> {
    let h = block.height;
    let meta = block
        .chain_metadata
        .as_ref()
        .ok_or(DetectorError::BadBlock {
            height: h,
            reason: "no chain metadata".into(),
        })?;
    let mut txs = Vec::with_capacity(block.vtx.len());
    let (mut n_orchard, mut n_ironwood) = (0u64, 0u64);
    for tx in &block.vtx {
        let orchard = tx
            .actions
            .iter()
            .map(|a| action(h, a))
            .collect::<Result<Vec<_>, _>>()?;
        let ironwood = tx
            .ironwood_actions
            .iter()
            .map(|a| action(h, a))
            .collect::<Result<Vec<_>, _>>()?;
        n_orchard += orchard.len() as u64;
        n_ironwood += ironwood.len() as u64;
        txs.push(zd_detect::CompactTx {
            txid: tx.txid.clone(),
            orchard,
            ironwood,
        });
    }
    let start = |end: u32, n: u64, pool: &str| {
        u64::from(end)
            .checked_sub(n)
            .ok_or(DetectorError::BadBlock {
                height: h,
                reason: format!("{pool} tree size {end} is smaller than the block's {n} actions"),
            })
    };
    Ok(zd_detect::CompactBlock {
        height: u32::try_from(h).map_err(|_| DetectorError::BadBlock {
            height: h,
            reason: "height out of range".into(),
        })?,
        hash: block.hash.clone(),
        orchard_tree_size: start(meta.orchard_commitment_tree_size, n_orchard, "orchard")?,
        ironwood_tree_size: start(meta.ironwood_commitment_tree_size, n_ironwood, "ironwood")?,
        txs,
    })
}

/// Where compact blocks come from. Implemented for lightwalletd; tests use an
/// in-memory source.
#[tonic::async_trait]
pub trait BlockSource: Send {
    /// Current chain tip height.
    async fn tip(&mut self) -> Result<u64, DetectorError>;
    /// Blocks `from..=to`, in order.
    async fn blocks(&mut self, from: u64, to: u64) -> Result<Vec<cf::CompactBlock>, DetectorError>;
}

#[tonic::async_trait]
impl BlockSource for CompactTxStreamerClient<Channel> {
    async fn tip(&mut self) -> Result<u64, DetectorError> {
        Ok(self
            .get_latest_block(ChainSpec {})
            .await
            .map_err(|e| DetectorError::Source(e.message().into()))?
            .into_inner()
            .height)
    }

    async fn blocks(&mut self, from: u64, to: u64) -> Result<Vec<cf::CompactBlock>, DetectorError> {
        let mut stream = self
            .get_block_range(BlockRange {
                start: Some(BlockId {
                    height: from,
                    hash: vec![],
                }),
                end: Some(BlockId {
                    height: to,
                    hash: vec![],
                }),
                pool_types: vec![PoolType::Orchard as i32, PoolType::Ironwood as i32],
            })
            .await
            .map_err(|e| DetectorError::Source(e.message().into()))?
            .into_inner();
        let mut out = Vec::new();
        while let Some(b) = stream
            .message()
            .await
            .map_err(|e| DetectorError::Source(e.message().into()))?
        {
            out.push(b);
        }
        Ok(out)
    }
}

/// Totals for one scanned range.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanSummary {
    /// Blocks scanned.
    pub blocks: u64,
    /// Notes reported.
    pub notes: u64,
    /// Nullifier batches reported.
    pub nullifier_batches: u64,
    /// Wallet state's answer to the note stream.
    pub notes_ack: IngestAck,
}

/// Scans `from..=to` and sends everything found to wallet state.
pub async fn scan_range<S: BlockSource>(
    source: &mut S,
    detector: &Detector,
    ingest: &mut WalletIngestClient<Channel>,
    from: u64,
    to: u64,
) -> Result<ScanSummary, DetectorError> {
    let blocks = source.blocks(from, to).await?;
    let mut report = BlockReport::default();
    let mut expected = from;
    for b in &blocks {
        if b.height != expected {
            return Err(DetectorError::Source(format!(
                "expected block {expected}, got {}",
                b.height
            )));
        }
        expected += 1;
        let r = detector.scan_block(&from_lightwalletd(b)?);
        report.notes.extend(r.notes);
        report.nullifiers.extend(r.nullifiers);
    }
    if expected != to + 1 {
        return Err(DetectorError::Source(format!(
            "range ended at {}, wanted {to}",
            expected.saturating_sub(1)
        )));
    }

    let summary = ScanSummary {
        blocks: blocks.len() as u64,
        notes: report.notes.len() as u64,
        nullifier_batches: report.nullifiers.len() as u64,
        notes_ack: IngestAck::default(),
    };
    // Nullifiers first, so wallet state never sees a note before the
    // nullifiers of the same block range.
    ingest
        .report_nullifiers(tokio_stream::iter(report.nullifiers))
        .await
        .map_err(|e| DetectorError::Ingest(e.message().into()))?;
    let ack = ingest
        .report_notes(tokio_stream::iter(report.notes))
        .await
        .map_err(|e| DetectorError::Ingest(e.message().into()))?
        .into_inner();
    Ok(ScanSummary {
        notes_ack: ack,
        ..summary
    })
}

/// Follows the chain from `next`: scans up to the tip in batches of
/// `batch` blocks, then polls every `poll`. Calls `checkpoint` with the next
/// height after each batch so the caller can persist it. Runs until an error.
pub async fn follow<S: BlockSource>(
    source: &mut S,
    detector: &Detector,
    ingest: &mut WalletIngestClient<Channel>,
    mut next: u64,
    batch: u64,
    poll: Duration,
    mut checkpoint: impl FnMut(u64) + Send,
) -> Result<(), DetectorError> {
    let batch = batch.max(1);
    loop {
        let tip = source.tip().await?;
        if tip < next {
            tokio::time::sleep(poll).await;
            continue;
        }
        let to = tip.min(next + batch - 1);
        scan_range(source, detector, ingest, next, to).await?;
        next = to + 1;
        checkpoint(next);
    }
}
