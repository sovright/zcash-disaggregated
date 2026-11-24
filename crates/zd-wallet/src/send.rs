//! Building and finishing a send.
//!
//! [`propose`] picks notes, builds the PCZT (Creator, Constructor and IO
//! Finalizer) with witnesses from the [`TreeTracker`], and returns it with
//! the notes it spends. [`authorize`] sends the PCZT to a prover and,
//! without witnesses, to the signer, in parallel, and combines the results.
//! [`extract`] checks every proof and signature and returns the transaction.
//! The caller marks the notes pending with [`WalletDb::mark_pending`] once it
//! decides to broadcast.

use orchard::ValuePool;
use orchard::keys::Scope;
use pczt::Pczt;
use pczt::roles::{
    combiner::Combiner, creator::Creator, io_finalizer::IoFinalizer, redactor::Redactor,
    tx_extractor::TransactionExtractor,
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use tonic::transport::Channel;
use zcash_primitives::transaction::{
    Transaction,
    builder::{BuildConfig, Builder, BundlePadding, PcztResult},
    fees::zip317,
};
use zcash_protocol::{
    consensus::{BlockHeight, Parameters},
    memo::MemoBytes,
    value::Zatoshis,
};
use zd_proto::v1::{
    AccountRef, ProveJob, SignJob, prove_result, prover_client::ProverClient, sign_result,
    signer_client::SignerClient,
};

use crate::{Account, Error, NoteRow, WalletDb, tree::TreeTracker};

/// A payment to make from one account.
#[derive(Clone, Debug)]
pub struct Payment {
    /// Recipient's Orchard-protocol receiver. The output goes to Ironwood.
    pub recipient: orchard::Address,
    /// Zatoshis to send.
    pub amount: u64,
    /// Memo for the recipient.
    pub memo: MemoBytes,
}

/// A built, unproved, unsigned transaction.
pub struct Proposal {
    /// The PCZT, ready for the prover and the signer.
    pub pczt: Pczt,
    /// Stored note ids it spends.
    pub note_ids: Vec<i64>,
    /// ZIP 317 fee.
    pub fee: u64,
    /// Change returned to the account's internal address.
    pub change: u64,
    /// Block the anchors are taken at.
    pub anchor_height: u32,
}

fn build_err(e: impl core::fmt::Debug) -> Error {
    Error::Build(format!("{e:?}"))
}

fn builder<P: Parameters>(
    params: P,
    target_height: u32,
    trees: &TreeTracker,
    account: &Account,
    notes: &[NoteRow],
    payment: &Payment,
    change: u64,
) -> Result<Builder<P, ()>, Error> {
    let has = |p| notes.iter().any(|n| n.pool == p);
    let orchard_anchor = if has(ValuePool::Orchard) {
        Some(trees.anchor(ValuePool::Orchard)?)
    } else {
        None
    };
    let mut b = Builder::new(
        params,
        BlockHeight::from_u32(target_height),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor,
            ironwood_anchor: Some(trees.anchor(ValuePool::Ironwood)?),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    let fvk = &account.fvk;
    for n in notes {
        let path = trees.witness(n.pool, n.position)?;
        match n.pool {
            ValuePool::Orchard => {
                b.add_orchard_spend::<zip317::FeeError>(fvk.clone(), n.note, path)
            }
            ValuePool::Ironwood => {
                b.add_ironwood_spend::<zip317::FeeError>(fvk.clone(), n.note, path)
            }
        }
        .map_err(build_err)?;
    }
    b.add_ironwood_output::<zip317::FeeError>(
        Some(fvk.to_ovk(Scope::External)),
        payment.recipient,
        Zatoshis::from_u64(payment.amount).map_err(build_err)?,
        payment.memo.clone(),
    )
    .map_err(build_err)?;
    if change > 0 {
        b.add_ironwood_output::<zip317::FeeError>(
            Some(fvk.to_ovk(Scope::Internal)),
            fvk.address_at(0u32, Scope::Internal),
            Zatoshis::from_u64(change).map_err(build_err)?,
            MemoBytes::empty(),
        )
        .map_err(build_err)?;
    }
    Ok(b)
}

/// Selects notes (Ironwood first, largest first) and builds the PCZT for
/// `payment`, with the ZIP 317 fee. Spends are witnessed at the trees' last
/// applied block; `target_height` is the height the transaction is built for
/// (normally the chain tip plus one).
pub fn propose<P: Parameters + Clone>(
    db: &WalletDb,
    trees: &TreeTracker,
    params: &P,
    target_height: u32,
    account_fp: &[u8; 32],
    payment: &Payment,
) -> Result<Proposal, Error> {
    let account = db.account(account_fp)?;
    let candidates = db.spendable_notes(account_fp)?;
    let available: u64 = candidates.iter().map(|n| n.note.value().inner()).sum();
    let fee_rule = zip317::FeeRule::standard();

    // The fee depends on the number of spends, which depends on the fee.
    // Grows monotonically, so a few rounds settle it.
    let mut fee = 0u64;
    for _ in 0..8 {
        let needed = payment
            .amount
            .checked_add(fee)
            .ok_or_else(|| Error::Build("amount overflows".into()))?;
        let mut sum = 0u64;
        let selected: Vec<NoteRow> = candidates
            .iter()
            .take_while(|n| {
                let take = sum < needed;
                sum += if take { n.note.value().inner() } else { 0 };
                take
            })
            .cloned()
            .collect();
        if sum < needed {
            return Err(Error::InsufficientFunds { available, needed });
        }
        let change = sum - needed;
        let b = builder(
            params.clone(),
            target_height,
            trees,
            &account,
            &selected,
            payment,
            change,
        )?;
        let required = u64::from(b.get_fee(&fee_rule).map_err(build_err)?);
        if required != fee {
            fee = required;
            continue;
        }
        let PcztResult { pczt_parts, .. } = b
            .build_for_pczt(UnwrapErr(SysRng), &fee_rule)
            .map_err(build_err)?;
        let pczt = Creator::build_from_parts(pczt_parts)
            .ok_or_else(|| Error::Build("creator rejected the parts".into()))?;
        let pczt = IoFinalizer::new(pczt)
            .finalize_io(UnwrapErr(SysRng))
            .map_err(build_err)?;
        return Ok(Proposal {
            pczt,
            note_ids: selected.iter().map(|n| n.id).collect(),
            fee,
            change,
            anchor_height: trees.height(),
        });
    }
    Err(Error::Build("fee did not settle".into()))
}

/// The PCZT a signer gets: no witnesses (signers need values, recipients and
/// alphas to run their policy, not the note's tree path).
pub fn for_signer(pczt: Pczt) -> Pczt {
    Redactor::new(pczt)
        .redact_orchard_with(|mut r| r.redact_actions(|mut a| a.clear_spend_witness()))
        .redact_ironwood_with(|mut r| r.redact_actions(|mut a| a.clear_spend_witness()))
        .finish()
}

/// Proves and signs in parallel, then combines.
pub async fn authorize(
    pczt: Pczt,
    account: AccountRef,
    job_id: Vec<u8>,
    memo: String,
    prover: &mut ProverClient<Channel>,
    signer: &mut SignerClient<Channel>,
) -> Result<Pczt, Error> {
    let full = pczt.clone().serialize().map_err(build_err)?;
    let redacted = for_signer(pczt).serialize().map_err(build_err)?;
    let remote = |role: &'static str, s: tonic::Status| Error::Remote {
        role,
        reason: s.message().to_string(),
    };
    let (proved, signed) = tokio::join!(
        prover.prove(ProveJob {
            job_id: job_id.clone(),
            account: Some(account.clone()),
            pczt: full,
            deadline_unix_ms: 0,
        }),
        signer.sign(SignJob {
            job_id,
            account: Some(account),
            pczt: redacted,
            memo,
        })
    );
    let proved = match proved
        .map_err(|s| remote("prover", s))?
        .into_inner()
        .outcome
    {
        Some(prove_result::Outcome::ProvedPczt(b)) => Pczt::parse(&b).map_err(build_err)?,
        Some(prove_result::Outcome::Error(reason)) => {
            return Err(Error::Remote {
                role: "prover",
                reason,
            });
        }
        None => {
            return Err(Error::Remote {
                role: "prover",
                reason: "empty result".into(),
            });
        }
    };
    let signed = match signed
        .map_err(|s| remote("signer", s))?
        .into_inner()
        .outcome
    {
        Some(sign_result::Outcome::SignedPczt(b)) => Pczt::parse(&b).map_err(build_err)?,
        Some(sign_result::Outcome::RejectedReason(reason)) => {
            return Err(Error::Remote {
                role: "signer",
                reason,
            });
        }
        None => {
            return Err(Error::Remote {
                role: "signer",
                reason: "empty result".into(),
            });
        }
    };
    Combiner::new(vec![proved, signed])
        .combine()
        .map_err(build_err)
}

/// Extracts the final transaction, verifying every proof and signature.
/// Returns the transaction and its serialization.
pub fn extract(pczt: Pczt) -> Result<(Transaction, Vec<u8>), Error> {
    let tx = TransactionExtractor::new(pczt)
        .extract(UnwrapErr(SysRng))
        .map_err(build_err)?;
    let mut raw = Vec::new();
    tx.write(&mut raw).map_err(build_err)?;
    Ok((tx, raw))
}
