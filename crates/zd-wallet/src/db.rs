//! SQLite storage.

use std::path::Path;

use orchard::keys::FullViewingKey;
use orchard::note::{NoteVersion, RandomSeed, Rho};
use orchard::value::NoteValue;
use rusqlite::{Connection, OptionalExtension, params};
use zcash_protocol::consensus::NetworkType;

use crate::Error;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS accounts (
    fingerprint BLOB PRIMARY KEY,
    network     INTEGER NOT NULL,
    ufvk        TEXT NOT NULL,
    qk          BLOB,
    label       TEXT NOT NULL DEFAULT '',
    birthday    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS notes (
    id            INTEGER PRIMARY KEY,
    account       BLOB NOT NULL REFERENCES accounts(fingerprint),
    pool          INTEGER NOT NULL,
    txid          BLOB NOT NULL,
    action_index  INTEGER NOT NULL,
    position      INTEGER NOT NULL,
    cmx           BLOB NOT NULL,
    height        INTEGER NOT NULL,
    block_hash    BLOB NOT NULL,
    scope         INTEGER NOT NULL,
    recipient     BLOB NOT NULL,
    value         INTEGER NOT NULL,
    rho           BLOB NOT NULL,
    rseed         BLOB NOT NULL,
    version       INTEGER NOT NULL,
    nullifier     BLOB NOT NULL,
    spent_height  INTEGER,
    pending_txid  BLOB,
    witnessable   INTEGER NOT NULL DEFAULT 1,
    UNIQUE (pool, cmx),
    UNIQUE (pool, nullifier)
);
CREATE TABLE IF NOT EXISTS spent_nullifiers (
    pool        INTEGER NOT NULL,
    nullifier   BLOB NOT NULL,
    height      INTEGER NOT NULL,
    block_hash  BLOB NOT NULL,
    PRIMARY KEY (pool, nullifier)
);
CREATE TABLE IF NOT EXISTS kv (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
"#;

fn net_code(n: NetworkType) -> i64 {
    match n {
        NetworkType::Main => 1,
        NetworkType::Test => 2,
        NetworkType::Regtest => 3,
    }
}

fn net_from(c: i64) -> NetworkType {
    match c {
        1 => NetworkType::Main,
        2 => NetworkType::Test,
        _ => NetworkType::Regtest,
    }
}

/// An account wallet state tracks.
#[derive(Clone, Debug)]
pub struct Account {
    /// `AccountRef.ufvk_fingerprint`.
    pub fingerprint: [u8; 32],
    /// Network.
    pub network: NetworkType,
    /// Orchard full viewing key.
    pub fvk: FullViewingKey,
    /// ZIP 2005 `qk`, kept for a future recovery statement.
    pub qk: Option<[u8; 32]>,
    /// Display label.
    pub label: String,
    /// First block that can contain the account's notes.
    pub birthday: u64,
}

/// A stored note.
#[derive(Clone, Debug)]
pub struct NoteRow {
    /// Row id.
    pub id: i64,
    /// Pool.
    pub pool: orchard::ValuePool,
    /// Position in the pool's commitment tree.
    pub position: u64,
    /// The note itself.
    pub note: orchard::Note,
    /// Height it was mined at.
    pub height: u64,
}

/// The wallet database.
pub struct WalletDb {
    conn: Connection,
}

impl WalletDb {
    /// Opens (creating if needed) a database file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute_batch(SCHEMA)?;
        Ok(WalletDb { conn })
    }

    /// An in-memory database, for tests.
    pub fn in_memory() -> Result<Self, Error> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(WalletDb { conn })
    }

    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    /// The raw connection, for tests and one-off inspection.
    #[doc(hidden)]
    pub fn conn_for_tests(&self) -> &Connection {
        &self.conn
    }

    /// Marks every note unconfirmed, before rebuilding the commitment trees
    /// (which confirm them again).
    pub fn mark_all_unconfirmed(&self) -> Result<(), Error> {
        self.conn.execute("UPDATE notes SET witnessable = 0", [])?;
        Ok(())
    }

    /// Adds an account from its UFVK. Returns the fingerprint.
    pub fn add_account(
        &self,
        ufvk: &str,
        qk: Option<[u8; 32]>,
        label: &str,
        birthday: u64,
    ) -> Result<[u8; 32], Error> {
        let (network, _) = zd_address::keys::parse_ufvk(ufvk)
            .ok_or_else(|| Error::Rejected("not a UFVK with an Orchard key".into()))?;
        let fp = zd_address::keys::fingerprint(ufvk);
        self.conn.execute(
            "INSERT OR IGNORE INTO accounts (fingerprint, network, ufvk, qk, label, birthday)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                fp.as_slice(),
                net_code(network),
                ufvk,
                qk.map(|q| q.to_vec()),
                label,
                birthday as i64
            ],
        )?;
        Ok(fp)
    }

    /// Looks up an account.
    pub fn account(&self, fingerprint: &[u8]) -> Result<Account, Error> {
        self.conn
            .query_row(
                "SELECT fingerprint, network, ufvk, qk, label, birthday FROM accounts
                 WHERE fingerprint = ?1",
                [fingerprint],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<Vec<u8>>>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()?
            .ok_or(Error::UnknownAccount)
            .and_then(|(fp, net, ufvk, qk, label, birthday)| {
                let (_, fvk) = zd_address::keys::parse_ufvk(&ufvk)
                    .ok_or_else(|| Error::Rejected("stored UFVK is invalid".into()))?;
                Ok(Account {
                    fingerprint: fp.try_into().map_err(|_| Error::UnknownAccount)?,
                    network: net_from(net),
                    fvk,
                    qk: qk.and_then(|q| q.try_into().ok()),
                    label,
                    birthday: birthday as u64,
                })
            })
    }

    /// The earliest birthday of any account.
    pub fn earliest_birthday(&self) -> Result<u64, Error> {
        self.conn
            .query_row("SELECT MIN(birthday) FROM accounts", [], |r| {
                r.get::<_, Option<i64>>(0)
            })?
            .map(|b| b as u64)
            .ok_or(Error::UnknownAccount)
    }

    /// Every account.
    pub fn accounts(&self) -> Result<Vec<Account>, Error> {
        let fps: Vec<Vec<u8>> = self
            .conn
            .prepare("SELECT fingerprint FROM accounts")?
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        fps.iter().map(|fp| self.account(fp)).collect()
    }

    /// Spendable balance (unspent, not pending, confirmed by the commitment
    /// tree) per pool: `(orchard, ironwood)`.
    pub fn balance(&self, fingerprint: &[u8]) -> Result<(u64, u64), Error> {
        let sum = |pool: orchard::ValuePool| -> Result<u64, Error> {
            Ok(self.conn.query_row(
                "SELECT COALESCE(SUM(value), 0) FROM notes
                 WHERE account = ?1 AND pool = ?2 AND spent_height IS NULL
                   AND pending_txid IS NULL AND witnessable = 1",
                params![fingerprint, crate::pool_code(pool)],
                |r| r.get::<_, i64>(0),
            )? as u64)
        };
        Ok((
            sum(orchard::ValuePool::Orchard)?,
            sum(orchard::ValuePool::Ironwood)?,
        ))
    }

    /// Unspent, not pending, witnessable notes, Ironwood first, largest first.
    pub fn spendable_notes(&self, fingerprint: &[u8]) -> Result<Vec<NoteRow>, Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, pool, position, recipient, value, rho, rseed, version, height
             FROM notes
             WHERE account = ?1 AND spent_height IS NULL AND pending_txid IS NULL
               AND witnessable = 1
             ORDER BY pool DESC, value DESC",
        )?;
        let rows = stmt.query_map([fingerprint], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Vec<u8>>(5)?,
                r.get::<_, Vec<u8>>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, i64>(8)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, pool, position, recipient, value, rho, rseed, version, height) = row?;
            let note = note_from_parts(&recipient, value as u64, &rho, &rseed, version as u32)
                .ok_or_else(|| Error::Rejected(format!("stored note {id} is invalid")))?;
            out.push(NoteRow {
                id,
                pool: crate::pool_of(pool as i32)?,
                position: position as u64,
                note,
                height: height as u64,
            });
        }
        Ok(out)
    }

    /// Marks notes as spent by a transaction we built but that is not mined
    /// yet, so they are not selected twice.
    pub fn mark_pending(&self, ids: &[i64], txid: &[u8]) -> Result<(), Error> {
        for id in ids {
            self.conn.execute(
                "UPDATE notes SET pending_txid = ?1 WHERE id = ?2",
                params![txid, id],
            )?;
        }
        Ok(())
    }

    /// Moves notes held under one id (a job id while building) to another
    /// (the txid once extracted).
    pub fn rename_pending(&self, from: &[u8], to: &[u8]) -> Result<usize, Error> {
        Ok(self.conn.execute(
            "UPDATE notes SET pending_txid = ?2 WHERE pending_txid = ?1",
            params![from, to],
        )?)
    }

    /// Releases notes held for a transaction that will not be broadcast.
    pub fn clear_pending(&self, txid: &[u8]) -> Result<usize, Error> {
        Ok(self.conn.execute(
            "UPDATE notes SET pending_txid = NULL WHERE pending_txid = ?1 AND spent_height IS NULL",
            [txid],
        )?)
    }

    /// Stores a small value.
    pub fn set_kv(&self, key: &str, value: &[u8]) -> Result<(), Error> {
        self.conn.execute(
            "INSERT INTO kv (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Reads a small value.
    pub fn kv(&self, key: &str) -> Result<Option<Vec<u8>>, Error> {
        Ok(self
            .conn
            .query_row("SELECT value FROM kv WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }
}

/// Rebuilds a note from stored or reported parts. `None` if inconsistent.
pub fn note_from_parts(
    recipient: &[u8],
    value: u64,
    rho: &[u8],
    rseed: &[u8],
    version: u32,
) -> Option<orchard::Note> {
    let recipient = Option::from(orchard::Address::from_raw_address_bytes(
        recipient.try_into().ok()?,
    ))?;
    let rho: Rho = Option::from(Rho::from_bytes(rho.try_into().ok()?))?;
    let rseed: RandomSeed = Option::from(RandomSeed::from_bytes(rseed.try_into().ok()?, &rho))?;
    let version = match version {
        2 => NoteVersion::V2,
        3 => NoteVersion::V3,
        _ => return None,
    };
    Option::from(orchard::Note::from_parts(
        recipient,
        NoteValue::from_raw(value),
        rho,
        rseed,
        version,
    ))
}
