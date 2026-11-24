//! Signing an Orchard-protocol spend whose randomizer `alpha` is already fixed
//! by the PCZT.
//!
//! In a PCZT (ZIP 374) the Constructor picks `alpha` for each spend and
//! publishes `rk = ak + [alpha] G` in the transaction, so the FROST quorum must
//! sign under exactly that `rk`. `frost-rerandomized` 3.0 only offers this
//! through a deprecated function, because its recommended flow derives the
//! randomizer from the signers' commitments to stop a coordinator from
//! choosing it after seeing them (ZcashFoundation/frost#1094).
//!
//! We get the same protection a different way: a signer commits to its nonces
//! only for a specific `(sighash, alpha)` taken from a PCZT it has already
//! checked, and [`sign`] refuses any signing package for a different message.
//! `alpha` is therefore fixed before any commitment exists.
//!
//! A transaction with several Orchard spends needs one run per spend, each
//! with that spend's `alpha` and the shared sighash.

use std::collections::BTreeMap;

use frost_rerandomized::{RandomizedParams, Randomizer};
use group::ff::PrimeField;
use pasta_curves::pallas;
use rand_core::{CryptoRng, RngCore};

use crate::{
    Error, Identifier, PallasBlake2b512, Signature, SigningPackage, VerifyingKey,
    keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare},
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
};

/// Why a spend signing step was refused.
#[derive(Debug, thiserror::Error)]
pub enum SpendSignError {
    /// The coordinator's signing package is for a different message than the
    /// one these nonces were committed for.
    #[error("signing package message does not match the committed sighash")]
    MessageMismatch,
    /// `alpha` is not a canonical Pallas scalar encoding.
    #[error("alpha is not a canonical Pallas scalar")]
    InvalidAlpha,
    /// An error from FROST itself (bad commitments, invalid share, ...).
    #[error(transparent)]
    Frost(#[from] Error),
}

/// Parses a 32-byte little-endian `alpha`, as stored in a PCZT Orchard spend.
pub fn alpha_from_bytes(bytes: &[u8; 32]) -> Result<pallas::Scalar, SpendSignError> {
    Option::from(pallas::Scalar::from_repr(*bytes)).ok_or(SpendSignError::InvalidAlpha)
}

fn params(group_key: &VerifyingKey, alpha: pallas::Scalar) -> RandomizedParams<PallasBlake2b512> {
    RandomizedParams::from_randomizer(group_key, Randomizer::from_scalar(alpha))
}

/// `rk = ak + [alpha] G`: the key the spend's signature must verify under.
pub fn randomized_verifying_key(group_key: &VerifyingKey, alpha: pallas::Scalar) -> VerifyingKey {
    *params(group_key, alpha).randomized_verifying_key()
}

/// Nonces bound to one spend. Consumed by [`sign`], so they cannot be reused.
pub struct BoundNonces {
    nonces: SigningNonces,
    sighash: [u8; 32],
    alpha: pallas::Scalar,
}

impl BoundNonces {
    /// The sighash these nonces may sign.
    pub fn sighash(&self) -> &[u8; 32] {
        &self.sighash
    }
    /// The spend's randomizer.
    pub fn alpha(&self) -> pallas::Scalar {
        self.alpha
    }
}

/// Round 1 for one spend: generates nonces bound to `(sighash, alpha)` and
/// the commitments to send to the coordinator.
///
/// Call this only after checking the PCZT the sighash and `alpha` came from.
pub fn commit<R: RngCore + CryptoRng>(
    key_package: &KeyPackage,
    sighash: [u8; 32],
    alpha: pallas::Scalar,
    rng: &mut R,
) -> (BoundNonces, SigningCommitments) {
    let (nonces, commitments) =
        frost_rerandomized::frost_core::round1::commit(key_package.signing_share(), rng);
    (
        BoundNonces {
            nonces,
            sighash,
            alpha,
        },
        commitments,
    )
}

/// Round 2 for one spend: a signature share under `rk = ak + [alpha] G`.
pub fn sign(
    nonces: BoundNonces,
    signing_package: &SigningPackage,
    key_package: &KeyPackage,
) -> Result<SignatureShare, SpendSignError> {
    if signing_package.message().as_slice() != nonces.sighash.as_slice() {
        return Err(SpendSignError::MessageMismatch);
    }
    let p = params(key_package.verifying_key(), nonces.alpha);
    // Same transformation as frost-rerandomized's (private) `Randomize`
    // impl: shift the share by alpha and every public key by [alpha] G.
    let alpha_g = *p.randomizer_element();
    let randomized = KeyPackage::new(
        *key_package.identifier(),
        SigningShare::new(key_package.signing_share().to_scalar() + nonces.alpha),
        VerifyingShare::new(key_package.verifying_share().to_element() + alpha_g),
        *p.randomized_verifying_key(),
        *key_package.min_signers(),
    );
    Ok(frost_rerandomized::frost_core::round2::sign(
        signing_package,
        &nonces.nonces,
        &randomized,
    )?)
}

/// Aggregates shares into the spend's `SpendAuthSig`, verifying it under `rk`.
pub fn aggregate(
    signing_package: &SigningPackage,
    shares: &BTreeMap<Identifier, SignatureShare>,
    public_key_package: &PublicKeyPackage,
    alpha: pallas::Scalar,
) -> Result<Signature, Error> {
    frost_rerandomized::aggregate(
        signing_package,
        shares,
        public_key_package,
        &params(public_key_package.verifying_key(), alpha),
    )
}

/// The 64-byte RedPallas encoding (`R || S`) for the PCZT's `spend_auth_sig`.
pub fn signature_bytes(sig: &Signature) -> [u8; 64] {
    sig.serialize()
        .expect("aggregate signatures always serialize")
        .try_into()
        .expect("RedPallas signatures are 64 bytes")
}
