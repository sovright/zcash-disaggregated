//! PCZT (ZIP 374) glue for the signer and prover roles of a disaggregated
//! Orchard-protocol wallet.
//!
//! - [`signing_request`] finds the Orchard and Ironwood spends a PCZT asks an
//!   account to authorize, with the transaction's sighash and each spend's
//!   `alpha`, after checking each spend's `rk` against the account's `ak`.
//! - [`frost`] runs one FROST signing per spend with `zd_frost::spend`.
//! - [`sign_with_ask`] signs as a 1/1 signer holding `ask` directly.
//! - [`apply_signatures`] writes signatures back into the PCZT.
//! - [`prove`] runs the Prover role. A prover learns the FVK of every spend
//!   (ZIP 374 Privacy Implications), so it belongs inside the customer's
//!   trust boundary.
//!
//! Signers here check only that the spends are the account's. Policy checks
//! on outputs and values (the PCZT Verifier role) are the caller's job and must
//! happen before [`frost::commit`] or [`sign_with_ask`].

use orchard::keys::SpendValidatingKey;
use orchard::primitives::redpallas::{Signature, SigningKey, SpendAuth};
use pasta_curves::pallas;
use pczt::Pczt;
use pczt::roles::signer::{Signer, SpendAuthSignature};
use pczt::roles::verifier::{OrchardError, Verifier};
use rand_core::{CryptoRng, Rng};

pub use orchard::ValuePool;

/// Why a PCZT could not be signed or proved.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `ak` is not a valid spend validating key.
    #[error("invalid ak")]
    InvalidAk,
    /// The PCZT still carries a dummy spending key; the IO Finalizer has not
    /// run. Signers must reject these (ZIP 374).
    #[error("PCZT has dummy spending keys; run the IO Finalizer first")]
    DummyKeysPresent,
    /// A spend's FVK is this account's, but its `rk` is not `ak + [alpha] G`.
    #[error("{pool:?} action {index}: rk does not match ak and alpha")]
    RkMismatch {
        /// Pool of the bad action.
        pool: ValuePool,
        /// Index within that pool's bundle.
        index: usize,
    },
    /// No spend in the PCZT belongs to this account.
    #[error("no spends for this account")]
    NothingToSign,
    /// The PCZT could not be parsed, or a role failed.
    #[error("PCZT {0}")]
    Pczt(String),
}

fn pczt_err(what: &str, e: impl core::fmt::Debug) -> Error {
    Error::Pczt(format!("{what}: {e:?}"))
}

/// One Orchard-protocol spend the account must authorize.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendToSign {
    /// Orchard or Ironwood.
    pub pool: ValuePool,
    /// Action index within that pool's bundle.
    pub action_index: usize,
    /// The spend's randomizer, fixed by the Constructor.
    pub alpha: pallas::Scalar,
    /// `rk = ak + [alpha] G`, as in the transaction.
    pub rk: [u8; 32],
}

/// Everything a signer needs from a PCZT: one sighash and the spends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningRequest {
    /// The shared shielded sighash every spend signature signs.
    pub sighash: [u8; 32],
    /// The account's spends, Orchard pool first.
    pub spends: Vec<SpendToSign>,
}

fn collect(
    bundle: &orchard::pczt::Bundle,
    pool: ValuePool,
    ak: &SpendValidatingKey,
    out: &mut Vec<SpendToSign>,
) -> Result<(), Error> {
    for (index, action) in bundle.actions().iter().enumerate() {
        let spend = action.spend();
        if spend.dummy_sk().is_some() {
            return Err(Error::DummyKeysPresent);
        }
        let ours_by_fvk = spend
            .fvk()
            .as_ref()
            .is_some_and(|fvk| fvk.to_bytes()[..32] == ak.to_bytes());
        let Some(alpha) = *spend.alpha() else {
            if ours_by_fvk {
                return Err(pczt_err("alpha missing", (pool, index)));
            }
            continue;
        };
        let expected: [u8; 32] = (&ak.randomize(&alpha)).into();
        let rk: [u8; 32] = spend.rk().into();
        if rk == expected {
            out.push(SpendToSign {
                pool,
                action_index: index,
                alpha,
                rk,
            });
        } else if ours_by_fvk {
            return Err(Error::RkMismatch { pool, index });
        }
    }
    Ok(())
}

/// Finds the spends in `pczt` that account `ak` must authorize.
///
/// A spend is the account's when its `rk` equals `ak + [alpha] G`. Spends
/// whose FVK names this account but whose `rk` does not match are an error.
pub fn signing_request(pczt: &Pczt, ak: &[u8; 32]) -> Result<SigningRequest, Error> {
    let ak = SpendValidatingKey::from_bytes(ak).ok_or(Error::InvalidAk)?;
    let sighash = Signer::new(pczt.clone())
        .map_err(|e| pczt_err("signer", e))?
        .shielded_sighash();

    let unwrap = |what: &str, e: OrchardError<Error>| match e {
        OrchardError::Custom(e) => e,
        e => pczt_err(what, e),
    };
    let mut spends = Vec::new();
    let v = Verifier::new(pczt.clone());
    let v = if pczt.orchard().actions().is_empty() {
        v
    } else {
        v.with_orchard(|b| {
            collect(b, ValuePool::Orchard, &ak, &mut spends).map_err(OrchardError::Custom)
        })
        .map_err(|e| unwrap("orchard bundle", e))?
    };
    if !pczt.ironwood().actions().is_empty() {
        v.with_ironwood(|b| {
            collect(b, ValuePool::Ironwood, &ak, &mut spends).map_err(OrchardError::Custom)
        })
        .map_err(|e| unwrap("ironwood bundle", e))?;
    }

    if spends.is_empty() {
        return Err(Error::NothingToSign);
    }
    Ok(SigningRequest { sighash, spends })
}

/// A finished signature for one spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendSignature {
    /// Orchard or Ironwood.
    pub pool: ValuePool,
    /// Action index within that pool's bundle.
    pub action_index: usize,
    /// RedPallas `SpendAuthSig`.
    pub signature: [u8; 64],
}

/// Applies spend signatures. Each is verified against its action's `rk`.
pub fn apply_signatures(pczt: Pczt, signatures: &[SpendSignature]) -> Result<Pczt, Error> {
    let mut signer = Signer::new(pczt).map_err(|e| pczt_err("signer", e))?;
    for s in signatures {
        signer
            .apply_orchard_spend_auth_signature(&SpendAuthSignature::from_parts(
                s.pool,
                s.action_index,
                s.signature,
            ))
            .map_err(|e| pczt_err("apply signature", e))?;
    }
    Ok(signer.finish())
}

/// 1/1 signer: signs every spend in `request` with `ask` (for example one
/// held in an HSM, already normalized so that ỹ(ak) = 0).
pub fn sign_with_ask<R: Rng + CryptoRng>(
    request: &SigningRequest,
    ask: &SigningKey<SpendAuth>,
    rng: &mut R,
) -> Vec<SpendSignature> {
    request
        .spends
        .iter()
        .map(|s| {
            let rsk = ask.randomize(&s.alpha);
            let sig: Signature<SpendAuth> = rsk.sign(&mut *rng, &request.sighash);
            SpendSignature {
                pool: s.pool,
                action_index: s.action_index,
                signature: (&sig).into(),
            }
        })
        .collect()
}

/// FROST signing over a [`SigningRequest`]: one `zd_frost::spend` run per
/// spend, all in the same two rounds.
pub mod frost {
    use std::collections::BTreeMap;

    use zd_frost::{
        Identifier, SigningPackage,
        keys::{KeyPackage, PublicKeyPackage},
        rand_core::{CryptoRng, RngCore},
        round1::SigningCommitments,
        round2::SignatureShare,
        spend::{self, BoundNonces, SpendSignError},
    };

    use super::{SigningRequest, SpendSignature};

    /// Round 1 for a participant: nonces bound to each spend, and the
    /// commitments to send to the coordinator (same order as `request.spends`).
    pub fn commit<R: RngCore + CryptoRng>(
        key_package: &KeyPackage,
        request: &SigningRequest,
        rng: &mut R,
    ) -> (Vec<BoundNonces>, Vec<SigningCommitments>) {
        request
            .spends
            .iter()
            .map(|s| spend::commit(key_package, request.sighash, s.alpha, rng))
            .unzip()
    }

    /// Coordinator: one signing package per spend from everyone's commitments.
    pub fn signing_packages(
        request: &SigningRequest,
        commitments: &BTreeMap<Identifier, Vec<SigningCommitments>>,
    ) -> Vec<SigningPackage> {
        (0..request.spends.len())
            .map(|i| {
                let c = commitments.iter().map(|(id, v)| (*id, v[i])).collect();
                SigningPackage::new(c, &request.sighash)
            })
            .collect()
    }

    /// Round 2 for a participant: one share per spend.
    pub fn sign(
        nonces: Vec<BoundNonces>,
        packages: &[SigningPackage],
        key_package: &KeyPackage,
    ) -> Result<Vec<SignatureShare>, SpendSignError> {
        if nonces.len() != packages.len() {
            return Err(SpendSignError::MessageMismatch);
        }
        nonces
            .into_iter()
            .zip(packages)
            .map(|(n, p)| spend::sign(n, p, key_package))
            .collect()
    }

    /// Coordinator: aggregates each spend's shares into its signature.
    pub fn aggregate(
        request: &SigningRequest,
        packages: &[SigningPackage],
        shares: &BTreeMap<Identifier, Vec<SignatureShare>>,
        public_key_package: &PublicKeyPackage,
    ) -> Result<Vec<SpendSignature>, zd_frost::Error> {
        request
            .spends
            .iter()
            .zip(packages)
            .enumerate()
            .map(|(i, (s, p))| {
                let these = shares.iter().map(|(id, v)| (*id, v[i])).collect();
                let sig = spend::aggregate(p, &these, public_key_package, s.alpha)?;
                Ok(SpendSignature {
                    pool: s.pool,
                    action_index: s.action_index,
                    signature: spend::signature_bytes(&sig),
                })
            })
            .collect()
    }
}

/// Prover role: creates whichever Orchard and Ironwood proofs the PCZT
/// needs, using the proving key for each pool's circuit version.
pub fn prove<R: Rng + CryptoRng>(
    pczt: Pczt,
    orchard_pk: Option<&orchard::circuit::ProvingKey>,
    ironwood_pk: Option<&orchard::circuit::ProvingKey>,
    rng: &mut R,
) -> Result<Pczt, Error> {
    let mut prover = pczt::roles::prover::Prover::new(pczt);
    if prover.requires_orchard_proof() {
        let pk = orchard_pk.ok_or_else(|| pczt_err("prove", "orchard proving key needed"))?;
        prover = prover
            .create_orchard_proof(&mut *rng, pk)
            .map_err(|e| pczt_err("orchard proof", e))?;
    }
    if prover.requires_ironwood_proof() {
        let pk = ironwood_pk.ok_or_else(|| pczt_err("prove", "ironwood proving key needed"))?;
        prover = prover
            .create_ironwood_proof(&mut *rng, pk)
            .map_err(|e| pczt_err("ironwood proof", e))?;
    }
    Ok(prover.finish())
}
