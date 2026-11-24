//! Commit-reveal generation of the shared `sk`, and transcript hashing.
//!
//! Each participant picks a random 32-byte contribution, broadcasts a
//! commitment to it, and only after every commitment has arrived reveals it.
//! `sk` is a hash of the transcript id and every reveal, so no participant can
//! choose it, and all participants end up with the same value.

use std::collections::BTreeMap;

use blake2b_simd::Params;
use zeroize::{Zeroize, ZeroizeOnDrop};

fn h256(personal: &[u8; 16], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Params::new().hash_length(32).personal(personal).to_state();
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Ceremony transcript id: hash of the encoded `CeremonyParams`.
pub fn transcript_id(encoded_params: &[u8]) -> [u8; 32] {
    h256(b"ZDisagg_Transcr_", &[encoded_params])
}

/// Commitment a participant broadcasts before revealing its contribution.
pub fn commit(transcript_id: &[u8; 32], participant: u32, contribution: &[u8; 32]) -> [u8; 32] {
    h256(
        b"ZDisagg_SkCommit",
        &[transcript_id, &participant.to_le_bytes(), contribution],
    )
}

/// Hash of a 96-byte raw FVK, for the confirmation round.
pub fn fvk_hash(raw_fvk: &[u8; 96]) -> [u8; 32] {
    h256(b"ZDisagg_FvkHash_", &[raw_fvk])
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CeremonyError {
    #[error("participant {0} did not commit")]
    MissingCommit(u32),
    #[error("participant {0} did not reveal")]
    MissingReveal(u32),
    #[error("participant {0} revealed a value that does not match its commitment")]
    BadReveal(u32),
    #[error("unexpected participant {0}")]
    UnknownParticipant(u32),
}

/// The shared secret all participants derive. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSk([u8; 32]);

impl SharedSk {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Checks every reveal against its commitment and combines them into `sk`.
///
/// `participants` is the full participant list from `CeremonyParams`; every
/// one of them must have committed and revealed.
pub fn combine(
    transcript_id: &[u8; 32],
    participants: &[u32],
    commits: &BTreeMap<u32, [u8; 32]>,
    reveals: &BTreeMap<u32, [u8; 32]>,
) -> Result<SharedSk, CeremonyError> {
    for id in commits.keys().chain(reveals.keys()) {
        if !participants.contains(id) {
            return Err(CeremonyError::UnknownParticipant(*id));
        }
    }
    let mut h = Params::new()
        .hash_length(32)
        .personal(b"ZDisagg_SharedSk")
        .to_state();
    h.update(transcript_id);
    let mut ids = participants.to_vec();
    ids.sort_unstable();
    ids.dedup();
    for id in ids {
        let c = commits.get(&id).ok_or(CeremonyError::MissingCommit(id))?;
        let r = reveals.get(&id).ok_or(CeremonyError::MissingReveal(id))?;
        if &commit(transcript_id, id, r) != c {
            return Err(CeremonyError::BadReveal(id));
        }
        h.update(&id.to_le_bytes());
        h.update(r);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    Ok(SharedSk(out))
}
