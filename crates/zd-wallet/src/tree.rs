//! The Orchard and Ironwood note commitment trees, built from lightwalletd's
//! compact blocks, for spend witnesses and anchors.
//!
//! The tracker is the second, detector-independent source of truth for notes:
//! when it applies a block, it marks a leaf only if a stored note claims that
//! position *and* has the same `cmx`, and only then does the note become
//! spendable. A stored note for this block that the chain does not confirm is
//! deleted.
//!
//! The trees live in memory and are rebuilt from the birthday's frontier on
//! start, which re-marks every stored note, including any reported after its
//! block was applied. Each applied block is a checkpoint (the last
//! [`MAX_CHECKPOINTS`] are kept), so a reorg up to that depth rewinds with
//! [`TreeTracker::rewind`].

use std::collections::HashMap;

use incrementalmerkletree::{Marking, Position, Retention, frontier::Frontier};
use orchard::ValuePool;
use orchard::note::ExtractedNoteCommitment;
use orchard::tree::MerkleHashOrchard;
use rusqlite::params;
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use zcash_client_backend::proto::{compact_formats as cf, service::TreeState};

use crate::{Error, WalletDb, pool_code};

/// Reorg depth the trees can rewind.
pub const MAX_CHECKPOINTS: usize = 100;

type Tree = ShardTree<MemoryShardStore<MerkleHashOrchard, u32>, 32, 16>;

fn tree_err(e: impl core::fmt::Debug) -> Error {
    Error::Tree(format!("{e:?}"))
}

struct PoolTree {
    tree: Tree,
    size: u64,
}

impl PoolTree {
    fn new(height: u32, frontier: Frontier<MerkleHashOrchard, 32>) -> Result<Self, Error> {
        let size = frontier.tree_size();
        let mut tree = Tree::new(MemoryShardStore::empty(), MAX_CHECKPOINTS);
        tree.insert_frontier(
            frontier,
            Retention::Checkpoint {
                id: height,
                marking: Marking::None,
            },
        )
        .map_err(tree_err)?;
        Ok(PoolTree { tree, size })
    }
}

/// Tree sizes `(orchard, ironwood)` and block hash at a kept checkpoint.
type Kept = ((u64, u64), Option<Vec<u8>>);

/// The two trees as of the last applied block.
pub struct TreeTracker {
    orchard: PoolTree,
    ironwood: PoolTree,
    height: u32,
    hash: Option<Vec<u8>>,
    /// Tree sizes and block hash at each kept checkpoint.
    history: HashMap<u32, Kept>,
}

/// Parses a 32-byte block hash shown in display (byte-reversed) hex.
fn display_hash(s: &str) -> Option<Vec<u8>> {
    let mut b = hex::decode(s).ok()?;
    if b.len() != 32 {
        return None;
    }
    b.reverse();
    Some(b)
}

impl TreeTracker {
    /// Starts from both trees' state at the end of block `height`.
    pub fn new(
        height: u32,
        hash: Option<Vec<u8>>,
        orchard: Frontier<MerkleHashOrchard, 32>,
        ironwood: Frontier<MerkleHashOrchard, 32>,
    ) -> Result<Self, Error> {
        let orchard = PoolTree::new(height, orchard)?;
        let ironwood = PoolTree::new(height, ironwood)?;
        let mut history = HashMap::new();
        history.insert(height, ((orchard.size, ironwood.size), hash.clone()));
        Ok(TreeTracker {
            orchard,
            ironwood,
            height,
            hash,
            history,
        })
    }

    /// Starts from lightwalletd's `GetTreeState` for the block before the
    /// account birthday.
    pub fn from_tree_state(ts: &TreeState) -> Result<Self, Error> {
        let height = u32::try_from(ts.height).map_err(tree_err)?;
        let orchard = ts.orchard_tree().map_err(tree_err)?.to_frontier();
        let ironwood = ts.ironwood_tree().map_err(tree_err)?.to_frontier();
        Self::new(height, display_hash(&ts.hash), orchard, ironwood)
    }

    /// Height of the last applied block.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Leaves in each tree: `(orchard, ironwood)`.
    pub fn sizes(&self) -> (u64, u64) {
        (self.orchard.size, self.ironwood.size)
    }

    fn pool(&mut self, pool: ValuePool) -> &mut PoolTree {
        match pool {
            ValuePool::Orchard => &mut self.orchard,
            ValuePool::Ironwood => &mut self.ironwood,
        }
    }

    fn pool_ref(&self, pool: ValuePool) -> &PoolTree {
        match pool {
            ValuePool::Orchard => &self.orchard,
            ValuePool::Ironwood => &self.ironwood,
        }
    }

    /// Appends the next block's note commitments, marking those that belong
    /// to stored notes, and checkpoints both trees at the block's height.
    ///
    /// Returns [`Error::Reorg`] if the block does not extend the last one.
    pub fn apply_block(&mut self, db: &WalletDb, block: &cf::CompactBlock) -> Result<(), Error> {
        let height = u32::try_from(block.height).map_err(tree_err)?;
        if height != self.height + 1 {
            return Err(Error::Tree(format!(
                "expected block {}, got {height}",
                self.height + 1
            )));
        }
        if let Some(h) = &self.hash
            && *h != block.prev_hash
        {
            return Err(Error::Reorg(u64::from(self.height)));
        }

        let mut confirmed = Vec::new();
        let mut unconfirmed = Vec::new();
        for (pool, actions) in [
            (
                ValuePool::Orchard,
                block
                    .vtx
                    .iter()
                    .flat_map(|t| &t.actions)
                    .collect::<Vec<_>>(),
            ),
            (
                ValuePool::Ironwood,
                block.vtx.iter().flat_map(|t| &t.ironwood_actions).collect(),
            ),
        ] {
            // Notes stored for this block and pool, by claimed position.
            let mut claimed: HashMap<u64, (i64, Vec<u8>)> = HashMap::new();
            {
                let mut stmt = db.conn().prepare(
                    "SELECT id, position, cmx FROM notes WHERE height = ?1 AND pool = ?2",
                )?;
                let rows = stmt.query_map(params![height as i64, pool_code(pool)], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get(2)?))
                })?;
                for row in rows {
                    let (id, pos, cmx) = row?;
                    claimed.insert(pos as u64, (id, cmx));
                }
            }
            let t = self.pool(pool);
            for a in actions {
                let bytes: [u8; 32] = a
                    .cmx
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Tree(format!("block {height}: cmx is not 32 bytes")))?;
                let cmx = Option::<ExtractedNoteCommitment>::from(
                    ExtractedNoteCommitment::from_bytes(&bytes),
                )
                .ok_or_else(|| Error::Tree(format!("block {height}: invalid cmx")))?;
                let mut retention = Retention::Ephemeral;
                if let Some((id, stored)) = claimed.remove(&t.size) {
                    if stored.as_slice() == bytes.as_slice() {
                        retention = Retention::Marked;
                        confirmed.push(id);
                    } else {
                        unconfirmed.push(id);
                    }
                }
                t.tree
                    .append(MerkleHashOrchard::from_cmx(&cmx), retention)
                    .map_err(tree_err)?;
                t.size += 1;
            }
            unconfirmed.extend(claimed.into_values().map(|(id, _)| id));
        }

        if let Some(meta) = &block.chain_metadata {
            let want = (
                u64::from(meta.orchard_commitment_tree_size),
                u64::from(meta.ironwood_commitment_tree_size),
            );
            if want != self.sizes() {
                return Err(Error::Tree(format!(
                    "block {height}: tree sizes {:?}, lightwalletd says {want:?}",
                    self.sizes()
                )));
            }
        }
        for p in [ValuePool::Orchard, ValuePool::Ironwood] {
            self.pool(p).tree.checkpoint(height).map_err(tree_err)?;
        }
        self.height = height;
        self.hash = Some(block.hash.clone());
        self.history
            .insert(height, (self.sizes(), self.hash.clone()));
        self.history
            .retain(|h, _| *h + MAX_CHECKPOINTS as u32 > height);

        let tx = db.conn().unchecked_transaction()?;
        for id in confirmed {
            tx.execute("UPDATE notes SET witnessable = 1 WHERE id = ?1", [id])?;
        }
        for id in unconfirmed {
            tx.execute("DELETE FROM notes WHERE id = ?1", [id])?;
        }
        tx.commit()?;
        db.set_kv("tree_height", &u64::from(height).to_le_bytes())?;
        Ok(())
    }

    /// Rewinds both trees to the end of block `height`. The caller must also
    /// call [`WalletDb::rewind`] with the same height.
    pub fn rewind(&mut self, height: u32) -> Result<(), Error> {
        let (sizes, hash) = self
            .history
            .get(&height)
            .cloned()
            .ok_or_else(|| Error::Tree(format!("no checkpoint at {height}; rebuild")))?;
        for p in [ValuePool::Orchard, ValuePool::Ironwood] {
            if !self
                .pool(p)
                .tree
                .truncate_to_checkpoint(&height)
                .map_err(tree_err)?
            {
                return Err(Error::Tree(format!("no checkpoint at {height}; rebuild")));
            }
        }
        (self.orchard.size, self.ironwood.size) = sizes;
        self.history.retain(|h, _| *h <= height);
        self.height = height;
        self.hash = hash;
        Ok(())
    }

    /// The anchor of `pool` as of the last applied block.
    pub fn anchor(&self, pool: ValuePool) -> Result<orchard::Anchor, Error> {
        self.pool_ref(pool)
            .tree
            .root_at_checkpoint_depth(Some(0))
            .map_err(tree_err)?
            .map(Into::into)
            .ok_or_else(|| Error::Tree("no checkpoint".into()))
    }

    /// A witness for the note at `position` in `pool`, as of the last applied
    /// block, so it matches [`Self::anchor`].
    pub fn witness(
        &self,
        pool: ValuePool,
        position: u64,
    ) -> Result<orchard::tree::MerklePath, Error> {
        self.pool_ref(pool)
            .tree
            .witness_at_checkpoint_depth(Position::from(position), 0)
            .map_err(tree_err)?
            .map(Into::into)
            .ok_or_else(|| Error::Tree("no checkpoint".into()))
    }
}
