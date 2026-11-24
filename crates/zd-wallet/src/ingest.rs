//! Checking and storing what detectors report.
//!
//! A detector holds only an IVK, so wallet state does not take its word for
//! anything it can check itself:
//!
//! - the note must rebuild from the reported parts, its commitment must be
//!   the reported `cmx`, and the recipient must be one of the account's
//!   addresses in the reported scope;
//! - the nullifier is computed here with `nk`, never reported;
//! - a note only becomes spendable once the commitment tree, built from
//!   lightwalletd's compact blocks independently of any detector, has the
//!   same `cmx` at the reported position (see [`crate::tree`]).
//!
//! So a dishonest detector can withhold notes but cannot invent one.

use orchard::keys::Scope;
use orchard::note::ExtractedNoteCommitment;
use rusqlite::params;
use zd_proto::v1::{NoteReport, NullifierBatch};

use crate::{Error, WalletDb, db::note_from_parts, pool_code, pool_of};

/// What happened to one report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingested {
    /// Stored.
    New,
    /// Already known.
    Duplicate,
}

fn scope_of(code: i32) -> Result<Scope, Error> {
    match zd_proto::v1::Scope::try_from(code) {
        Ok(zd_proto::v1::Scope::External) => Ok(Scope::External),
        Ok(zd_proto::v1::Scope::Internal) => Ok(Scope::Internal),
        _ => Err(Error::Rejected(format!("unknown scope {code}"))),
    }
}

fn scope_code(scope: Scope) -> i64 {
    match scope {
        Scope::External => zd_proto::v1::Scope::External as i64,
        Scope::Internal => zd_proto::v1::Scope::Internal as i64,
    }
}

impl WalletDb {
    /// Checks one note report against the account's FVK and stores it.
    ///
    /// The note is stored as not yet witnessable; the tree tracker flips that
    /// once it has seen the same commitment at the same position on chain.
    pub fn ingest_note(&self, r: &NoteReport) -> Result<Ingested, Error> {
        let fp = r
            .account
            .as_ref()
            .ok_or_else(|| Error::Rejected("no account".into()))?
            .ufvk_fingerprint
            .clone();
        let account = self.account(&fp)?;
        let pool = pool_of(r.pool)?;
        let scope = scope_of(r.scope)?;
        let note = note_from_parts(&r.recipient, r.value_zat, &r.rho, &r.rseed, r.note_version)
            .ok_or_else(|| Error::Rejected("note parts do not form a note".into()))?;
        let cmx = ExtractedNoteCommitment::from(note.commitment()).to_bytes();
        if r.cmx.as_slice() != cmx.as_slice() {
            return Err(Error::Rejected("cmx does not match the note".into()));
        }
        if account.fvk.scope_for_address(&note.recipient()) != Some(scope) {
            return Err(Error::Rejected(
                "recipient is not the account's address in that scope".into(),
            ));
        }
        if r.block_hash.len() != 32 || r.txid.len() != 32 {
            return Err(Error::Rejected("bad block hash or txid length".into()));
        }
        let nf = note.nullifier(&account.fvk).to_bytes();
        let pool_c = pool_code(pool);

        let tx = self.conn().unchecked_transaction()?;
        let n = tx.execute(
            "INSERT OR IGNORE INTO notes (account, pool, txid, action_index, position, cmx,
                height, block_hash, scope, recipient, value, rho, rseed, version, nullifier,
                witnessable)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, 0)",
            params![
                fp,
                pool_c,
                r.txid,
                r.action_index as i64,
                r.commitment_position as i64,
                cmx.as_slice(),
                r.height as i64,
                r.block_hash,
                scope_code(scope),
                r.recipient,
                r.value_zat as i64,
                r.rho,
                r.rseed,
                r.note_version as i64,
                nf.as_slice(),
            ],
        )?;
        if n == 1 {
            // The spend may have been reported before the note.
            tx.execute(
                "UPDATE notes SET spent_height = (
                    SELECT height FROM spent_nullifiers WHERE pool = ?1 AND nullifier = ?2)
                 WHERE pool = ?1 AND nullifier = ?2",
                params![pool_c, nf.as_slice()],
            )?;
        }
        tx.commit()?;
        Ok(if n == 1 {
            Ingested::New
        } else {
            Ingested::Duplicate
        })
    }

    /// Records a block's revealed nullifiers and marks matching notes spent.
    /// Returns how many of our notes this spent.
    pub fn ingest_nullifiers(&self, b: &NullifierBatch) -> Result<u64, Error> {
        let pool = pool_code(pool_of(b.pool)?);
        let tx = self.conn().unchecked_transaction()?;
        let mut spent = 0;
        {
            let mut ins = tx.prepare(
                "INSERT OR IGNORE INTO spent_nullifiers (pool, nullifier, height, block_hash)
                 VALUES (?1, ?2, ?3, ?4)",
            )?;
            let mut upd = tx.prepare(
                "UPDATE notes SET spent_height = ?3, pending_txid = NULL
                 WHERE pool = ?1 AND nullifier = ?2 AND spent_height IS NULL",
            )?;
            for nf in &b.nullifiers {
                if nf.len() != 32 {
                    return Err(Error::Rejected("nullifier is not 32 bytes".into()));
                }
                ins.execute(params![pool, nf, b.height as i64, b.block_hash])?;
                spent += upd.execute(params![pool, nf, b.height as i64])? as u64;
            }
        }
        tx.commit()?;
        Ok(spent)
    }

    /// Forgets everything above `height` after a reorg: notes mined there,
    /// spends recorded there. Detectors must rescan from `height + 1`.
    pub fn rewind(&self, height: u64) -> Result<(), Error> {
        let h = height as i64;
        let tx = self.conn().unchecked_transaction()?;
        tx.execute("DELETE FROM notes WHERE height > ?1", [h])?;
        tx.execute(
            "UPDATE notes SET spent_height = NULL WHERE spent_height > ?1",
            [h],
        )?;
        tx.execute("DELETE FROM spent_nullifiers WHERE height > ?1", [h])?;
        tx.commit()?;
        Ok(())
    }
}
