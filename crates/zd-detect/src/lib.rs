//! Note detection with only incoming viewing keys.
//!
//! A detector holds the account's external and internal Orchard-protocol IVKs
//! (from the UIVK in `ViewingExport`) and nothing else. It trial-decrypts the
//! compact form of every Orchard and Ironwood action (as served by
//! lightwalletd) and reports the notes it can open, plus every revealed
//! nullifier, to wallet state.
//!
//! An IVK cannot compute nullifiers, so a detector cannot tell which notes are
//! spent. It forwards each block's nullifiers instead and wallet state, which
//! holds `nk`, matches them. Wallet state also re-checks each reported note
//! against the chain (`cmx`), so a dishonest detector can withhold notes but
//! cannot invent them; running several detectors covers withholding.
//!
//! Compact actions omit the memo. Wallet state fetches the full transaction
//! when it needs one.

use orchard::keys::{IncomingViewingKey, PreparedIncomingViewingKey};
use orchard::note::{ExtractedNoteCommitment, NoteVersion, Nullifier};
use orchard::note_encryption::{CompactAction, IronwoodDomain, OrchardDomain};
use zcash_note_encryption::{EphemeralKeyBytes, try_compact_note_decryption};
use zd_proto::v1::{AccountRef, NoteReport, NullifierBatch, Pool, Scope};

/// One compact Orchard-protocol action as it appears in a lightwalletd
/// `CompactOrchardAction`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactActionBytes {
    /// Nullifier of the note this action spends.
    pub nullifier: [u8; 32],
    /// Extracted commitment of the note this action creates.
    pub cmx: [u8; 32],
    /// Ephemeral public key.
    pub ephemeral_key: [u8; 32],
    /// First 52 bytes of the note ciphertext.
    pub ciphertext: [u8; 52],
}

/// One transaction's compact actions in each pool.
#[derive(Clone, Debug, Default)]
pub struct CompactTx {
    /// Transaction id (as lightwalletd reports it).
    pub txid: Vec<u8>,
    /// Orchard pool actions, in order.
    pub orchard: Vec<CompactActionBytes>,
    /// Ironwood pool actions, in order.
    pub ironwood: Vec<CompactActionBytes>,
}

/// One block, with each pool's commitment tree size before the block (from
/// lightwalletd's chain metadata) so the detector can report positions.
#[derive(Clone, Debug, Default)]
pub struct CompactBlock {
    /// Block height.
    pub height: u32,
    /// Block hash.
    pub hash: Vec<u8>,
    /// Orchard tree size before this block.
    pub orchard_tree_size: u64,
    /// Ironwood tree size before this block.
    pub ironwood_tree_size: u64,
    /// Transactions in block order.
    pub txs: Vec<CompactTx>,
}

/// What a detector emits for one block.
#[derive(Clone, Debug, Default)]
pub struct BlockReport {
    /// Notes the IVKs opened.
    pub notes: Vec<NoteReport>,
    /// Every nullifier revealed in the block, per pool (pools with none are
    /// omitted).
    pub nullifiers: Vec<NullifierBatch>,
}

/// Why an action was skipped.
#[derive(Debug, PartialEq, Eq)]
pub enum MalformedAction {
    /// Not a canonical nullifier encoding.
    Nullifier,
    /// Not a canonical note commitment encoding.
    Cmx,
}

/// Trial-decrypts actions for one account.
pub struct Detector {
    account: AccountRef,
    external: PreparedIncomingViewingKey,
    internal: PreparedIncomingViewingKey,
}

fn pool_code(pool: orchard::ValuePool) -> Pool {
    match pool {
        orchard::ValuePool::Orchard => Pool::Orchard,
        orchard::ValuePool::Ironwood => Pool::Ironwood,
    }
}

impl Detector {
    /// A detector for `account` from its external and internal IVKs.
    pub fn new(
        account: AccountRef,
        external: &IncomingViewingKey,
        internal: &IncomingViewingKey,
    ) -> Self {
        Detector {
            account,
            external: external.prepare(),
            internal: internal.prepare(),
        }
    }

    /// Trial-decrypts one action. Returns the report fields that depend only
    /// on the action (block, txid and position are filled in by
    /// [`Detector::scan_block`]).
    pub fn try_action(
        &self,
        pool: orchard::ValuePool,
        a: &CompactActionBytes,
    ) -> Result<Option<NoteReport>, MalformedAction> {
        let nf =
            Option::from(Nullifier::from_bytes(&a.nullifier)).ok_or(MalformedAction::Nullifier)?;
        let cmx = Option::from(ExtractedNoteCommitment::from_bytes(&a.cmx))
            .ok_or(MalformedAction::Cmx)?;
        let action =
            CompactAction::from_parts(nf, cmx, EphemeralKeyBytes(a.ephemeral_key), a.ciphertext);

        for (ivk, scope) in [
            (&self.external, Scope::External),
            (&self.internal, Scope::Internal),
        ] {
            let found = match pool {
                orchard::ValuePool::Orchard => try_compact_note_decryption(
                    &OrchardDomain::for_compact_action(&action),
                    ivk,
                    &action,
                ),
                orchard::ValuePool::Ironwood => try_compact_note_decryption(
                    &IronwoodDomain::for_compact_action(&action),
                    ivk,
                    &action,
                ),
            };
            if let Some((note, recipient)) = found {
                return Ok(Some(NoteReport {
                    account: Some(self.account.clone()),
                    pool: pool_code(pool) as i32,
                    cmx: a.cmx.to_vec(),
                    scope: scope as i32,
                    recipient: recipient.to_raw_address_bytes().to_vec(),
                    value_zat: note.value().inner(),
                    rho: note.rho().to_bytes().to_vec(),
                    rseed: note.rseed().as_bytes().to_vec(),
                    note_version: match note.version() {
                        NoteVersion::V2 => 2,
                        NoteVersion::V3 => 3,
                    },
                    ..Default::default()
                }));
            }
        }
        Ok(None)
    }

    /// Scans a block: every note the IVKs open, with its commitment tree
    /// position, and every nullifier. Malformed actions are skipped (and still
    /// advance the tree position, since the chain committed them).
    pub fn scan_block(&self, block: &CompactBlock) -> BlockReport {
        let mut report = BlockReport::default();
        for (pool, start) in [
            (orchard::ValuePool::Orchard, block.orchard_tree_size),
            (orchard::ValuePool::Ironwood, block.ironwood_tree_size),
        ] {
            let mut position = start;
            let mut nullifiers = Vec::new();
            for tx in &block.txs {
                let actions = match pool {
                    orchard::ValuePool::Orchard => &tx.orchard,
                    orchard::ValuePool::Ironwood => &tx.ironwood,
                };
                for (index, a) in actions.iter().enumerate() {
                    nullifiers.push(a.nullifier.to_vec());
                    if let Ok(Some(mut note)) = self.try_action(pool, a) {
                        note.height = block.height;
                        note.block_hash = block.hash.clone();
                        note.txid = tx.txid.clone();
                        note.action_index = index as u32;
                        note.commitment_position = position;
                        report.notes.push(note);
                    }
                    position += 1;
                }
            }
            if !nullifiers.is_empty() {
                report.nullifiers.push(NullifierBatch {
                    height: block.height,
                    block_hash: block.hash.clone(),
                    pool: pool_code(pool) as i32,
                    nullifiers,
                });
            }
        }
        report
    }
}
