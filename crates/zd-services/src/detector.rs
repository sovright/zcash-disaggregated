//! The detector daemon: compact blocks in (from lightwalletd), note and
//! nullifier reports out (to wallet state's `WalletIngest`).
//!
//! The detector's only state is a [`Cursor`], which the caller persists. One
//! detector process can serve many accounts: every block is trial-decrypted
//! once per account, and its nullifiers are sent once.
//!
//! Reorgs are handled two ways:
//!
//! - The detector checks that each block's `prev_hash` is the previous
//!   block's hash. If not, it steps back [`FollowConfig::reorg_rewind`]
//!   blocks and rescans, before reporting anything from the new blocks.
//! - Wallet state is the authority. When its commitment trees hit a reorg it
//!   forgets reports above the fork and bumps its reorg epoch; every
//!   `IngestAck` carries the epoch and the height to rescan from, and a
//!   detector that sees a newer epoch goes back to that height.

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
    /// Block `height` does not extend the block before it.
    #[error("reorg at block {height}")]
    Reorg {
        /// First block that does not link.
        height: u64,
    },
    /// No accounts to scan for.
    #[error("no accounts")]
    NoAccounts,
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
    /// Wallet state's answer to the nullifier stream.
    pub nullifiers_ack: IngestAck,
    /// Wallet state's answer to the note stream.
    pub notes_ack: IngestAck,
    /// Hash of the last block scanned.
    pub last_hash: Vec<u8>,
}

/// Scans `from..=to` for every detector's account and sends everything found
/// to wallet state.
///
/// `prev_hash` is the hash of block `from - 1` if the caller knows it; if
/// not, that block is fetched to learn it. Returns [`DetectorError::Reorg`]
/// without reporting anything if the blocks do not form a chain on top of it.
pub async fn scan_range<S: BlockSource>(
    source: &mut S,
    detectors: &[Detector],
    ingest: &mut WalletIngestClient<Channel>,
    from: u64,
    to: u64,
    prev_hash: Option<&[u8]>,
) -> Result<ScanSummary, DetectorError> {
    if detectors.is_empty() {
        return Err(DetectorError::NoAccounts);
    }
    let fetch_from = if prev_hash.is_none() && from > 0 {
        from - 1
    } else {
        from
    };
    let mut blocks = source.blocks(fetch_from, to).await?;
    let mut expected_prev = prev_hash.map(<[u8]>::to_vec);
    if fetch_from < from {
        if blocks.first().map(|b| b.height) != Some(fetch_from) {
            return Err(DetectorError::Source(format!("block {fetch_from} missing")));
        }
        expected_prev = Some(blocks.remove(0).hash);
    }

    let mut report = BlockReport::default();
    let mut expected = from;
    for b in &blocks {
        if b.height != expected {
            return Err(DetectorError::Source(format!(
                "expected block {expected}, got {}",
                b.height
            )));
        }
        if let Some(prev) = &expected_prev
            && *prev != b.prev_hash
        {
            return Err(DetectorError::Reorg { height: b.height });
        }
        expected_prev = Some(b.hash.clone());
        expected += 1;
        let block = from_lightwalletd(b)?;
        for (i, d) in detectors.iter().enumerate() {
            let r = d.scan_block(&block);
            report.notes.extend(r.notes);
            // Nullifiers are the same for every account; send them once.
            if i == 0 {
                report.nullifiers.extend(r.nullifiers);
            }
        }
    }
    if expected != to + 1 {
        return Err(DetectorError::Source(format!(
            "range ended at {}, wanted {to}",
            expected.saturating_sub(1)
        )));
    }

    let mut summary = ScanSummary {
        blocks: blocks.len() as u64,
        notes: report.notes.len() as u64,
        nullifier_batches: report.nullifiers.len() as u64,
        last_hash: blocks.last().map(|b| b.hash.clone()).unwrap_or_default(),
        ..Default::default()
    };
    // Nullifiers first, so wallet state never sees a note before the
    // nullifiers of the same block range.
    summary.nullifiers_ack = ingest
        .report_nullifiers(tokio_stream::iter(report.nullifiers))
        .await
        .map_err(|e| DetectorError::Ingest(e.message().into()))?
        .into_inner();
    summary.notes_ack = ingest
        .report_notes(tokio_stream::iter(report.notes))
        .await
        .map_err(|e| DetectorError::Ingest(e.message().into()))?
        .into_inner();
    Ok(summary)
}

/// Where a detector is. Persist it after every batch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cursor {
    /// Next height to scan.
    pub next: u64,
    /// Hash of block `next - 1`, if known.
    pub prev_hash: Option<Vec<u8>>,
    /// Wallet state's reorg epoch as last seen; `None` for a new detector,
    /// which adopts wallet state's epoch without rescanning.
    pub reorg_epoch: Option<u64>,
}

impl Cursor {
    /// A new detector starting at `next`.
    pub fn starting_at(next: u64) -> Self {
        Cursor {
            next,
            ..Default::default()
        }
    }

    /// Applies wallet state's reorg epoch from an ack. Returns `true` if the
    /// detector must go back.
    pub fn apply_ack(&mut self, ack: &IngestAck) -> bool {
        let Some(seen) = self.reorg_epoch else {
            self.reorg_epoch = Some(ack.reorg_epoch);
            return false;
        };
        if ack.reorg_epoch <= seen {
            return false;
        }
        self.reorg_epoch = Some(ack.reorg_epoch);
        let from = u64::from(ack.rescan_from);
        if from > 0 && from < self.next {
            self.next = from;
            self.prev_hash = None;
            return true;
        }
        false
    }
}

/// How a detector follows the chain.
#[derive(Clone, Copy, Debug)]
pub struct FollowConfig {
    /// Blocks per batch.
    pub batch: u64,
    /// Poll interval at the tip.
    pub poll: Duration,
    /// Blocks to step back when the chain does not link.
    pub reorg_rewind: u64,
}

impl Default for FollowConfig {
    fn default() -> Self {
        FollowConfig {
            batch: 100,
            poll: Duration::from_secs(15),
            reorg_rewind: 10,
        }
    }
}

/// Follows the chain from `cursor`: scans up to the tip in batches, then
/// polls. Calls `checkpoint` with the cursor after each batch (and after
/// each rewind) so the caller can persist it. Runs until an error, which
/// leaves the last checkpoint valid to resume from.
pub async fn follow<S: BlockSource>(
    source: &mut S,
    detectors: &[Detector],
    ingest: &mut WalletIngestClient<Channel>,
    mut cursor: Cursor,
    cfg: FollowConfig,
    mut checkpoint: impl FnMut(&Cursor) + Send,
) -> Result<(), DetectorError> {
    let batch = cfg.batch.max(1);
    loop {
        let tip = source.tip().await?;
        if tip < cursor.next {
            tokio::time::sleep(cfg.poll).await;
            continue;
        }
        let to = tip.min(cursor.next + batch - 1);
        match scan_range(
            source,
            detectors,
            ingest,
            cursor.next,
            to,
            cursor.prev_hash.as_deref(),
        )
        .await
        {
            Ok(s) => {
                cursor.next = to + 1;
                cursor.prev_hash = Some(s.last_hash);
                for ack in [&s.nullifiers_ack, &s.notes_ack] {
                    if cursor.apply_ack(ack) {
                        tracing::warn!(
                            rescan_from = cursor.next,
                            epoch = ack.reorg_epoch,
                            "wallet state rewound past a reorg; rescanning"
                        );
                    }
                }
            }
            Err(DetectorError::Reorg { height }) => {
                cursor.next = height.saturating_sub(cfg.reorg_rewind).max(1);
                cursor.prev_hash = None;
                tracing::warn!(at = height, rescan_from = cursor.next, "reorg; rescanning");
            }
            Err(e) => return Err(e),
        }
        checkpoint(&cursor);
    }
}
