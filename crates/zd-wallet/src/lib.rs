//! Wallet state: the one role that holds the full viewing key.
//!
//! - Accepts `NoteReport`s from any number of detectors and re-derives each
//!   note's commitment and the recipient's scope, so a detector can withhold
//!   notes but cannot invent them. Computes each note's nullifier with `nk`.
//! - Matches `NullifierBatch`es against stored notes to track spends.
//! - Maintains the Orchard and Ironwood note commitment trees from compact
//!   blocks (see [`tree`]) to produce spend witnesses.
//! - Builds PCZTs and runs the send flow (see [`send`]).
//!
//! Storage is SQLite. The commitment trees are kept in memory and rebuilt
//! from the account birthday's frontier on start.

pub mod db;
pub mod ingest;
pub mod send;
pub mod server;
pub mod tree;

pub use db::{Account, NoteRow, WalletDb};

/// Wallet state errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Database failure.
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
    /// A report did not check out against the account's keys.
    #[error("rejected report: {0}")]
    Rejected(String),
    /// Unknown account.
    #[error("unknown account")]
    UnknownAccount,
    /// Commitment tree failure or inconsistency.
    #[error("tree: {0}")]
    Tree(String),
    /// The next block does not extend the last applied one: a reorg. Rewind
    /// to an earlier height and rescan.
    #[error("reorg below height {0}")]
    Reorg(u64),
    /// Not enough spendable value.
    #[error("insufficient funds: have {available}, need {needed}")]
    InsufficientFunds {
        /// Spendable zatoshis.
        available: u64,
        /// Zatoshis needed including the fee.
        needed: u64,
    },
    /// Transaction construction failed.
    #[error("build: {0}")]
    Build(String),
    /// A remote role failed or refused.
    #[error("{role}: {reason}")]
    Remote {
        /// Which role.
        role: &'static str,
        /// What it said.
        reason: String,
    },
}

/// Convenience for reports that only need the pool code.
pub(crate) fn pool_of(code: i32) -> Result<orchard::ValuePool, Error> {
    match zd_proto::v1::Pool::try_from(code) {
        Ok(zd_proto::v1::Pool::Orchard) => Ok(orchard::ValuePool::Orchard),
        Ok(zd_proto::v1::Pool::Ironwood) => Ok(orchard::ValuePool::Ironwood),
        _ => Err(Error::Rejected(format!("unknown pool {code}"))),
    }
}

pub(crate) fn pool_code(pool: orchard::ValuePool) -> i64 {
    match pool {
        orchard::ValuePool::Orchard => zd_proto::v1::Pool::Orchard as i64,
        orchard::ValuePool::Ironwood => zd_proto::v1::Pool::Ironwood as i64,
    }
}
