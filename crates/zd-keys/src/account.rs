//! Assembling an Orchard-protocol full viewing key from a FROST or HSM `ak`
//! and a shared `sk`, using the ZIP 2005 `use_qsk = true` path.

use ff::PrimeField;
use orchard::keys::{FullViewingKey, SpendValidatingKey};
use pasta_curves::pallas;
use zeroize::Zeroize;

use crate::zip2005::{self, Qk, Qsk};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// `ak` is not a valid spend validating key: identity, off-curve, or its
    /// encoding has ỹ = 1 (FROST participants must negate their shares first).
    #[error("invalid spend validating key ak")]
    InvalidAk,
    /// The derived `ivk` (external or internal) is 0 or ⊥. Astronomically
    /// unlikely; restart the ceremony with a fresh `sk`.
    #[error("derived incoming viewing key is invalid; rerun the ceremony")]
    InvalidIvk,
}

/// The public-side key material of a quantum-recoverable account: everything
/// except `ask` (held as shares or in an HSM) and `qsk`/`sk` (held by
/// participants).
#[derive(Clone, Debug)]
pub struct AccountKeys {
    ak: [u8; 32],
    nk: pallas::Base,
    qk: Qk,
    rivk: pallas::Scalar,
    fvk: FullViewingKey,
}

impl AccountKeys {
    /// Derives the account from the shared `sk` and the group key `ak`.
    ///
    /// Returns the keys and `qsk`, which the caller must store with its
    /// `ask` share and must not send anywhere.
    pub fn derive(sk: &[u8; 32], ak: [u8; 32]) -> Result<(Self, Qsk), Error> {
        SpendValidatingKey::from_bytes(&ak).ok_or(Error::InvalidAk)?;
        let nk = zip2005::nk(sk);
        let qsk = zip2005::qsk(sk);
        let qk = zip2005::qk(&qsk);
        let rivk = zip2005::rivk_ext(&qk, &ak, &nk);
        let keys = Self::from_parts(ak, nk, qk, rivk)?;
        Ok((keys, qsk))
    }

    /// Rebuilds the account from what wallet state stores (`ak`, `nk`, `qk`),
    /// recomputing `rivk_ext` so a tampered export is caught.
    pub fn from_host_parts(ak: [u8; 32], nk: pallas::Base, qk: Qk) -> Result<Self, Error> {
        SpendValidatingKey::from_bytes(&ak).ok_or(Error::InvalidAk)?;
        let rivk = zip2005::rivk_ext(&qk, &ak, &nk);
        Self::from_parts(ak, nk, qk, rivk)
    }

    fn from_parts(
        ak: [u8; 32],
        nk: pallas::Base,
        qk: Qk,
        rivk: pallas::Scalar,
    ) -> Result<Self, Error> {
        let mut raw = [0u8; 96];
        raw[..32].copy_from_slice(&ak);
        raw[32..64].copy_from_slice(&nk.to_repr());
        raw[64..].copy_from_slice(&rivk.to_repr());
        let fvk = FullViewingKey::from_bytes(&raw).ok_or(Error::InvalidIvk);
        raw.zeroize();
        Ok(AccountKeys {
            ak,
            nk,
            qk,
            rivk,
            fvk: fvk?,
        })
    }

    pub fn ak(&self) -> &[u8; 32] {
        &self.ak
    }
    pub fn nk(&self) -> pallas::Base {
        self.nk
    }
    pub fn qk(&self) -> &Qk {
        &self.qk
    }
    pub fn rivk(&self) -> pallas::Scalar {
        self.rivk
    }
    pub fn fvk(&self) -> &FullViewingKey {
        &self.fvk
    }

    /// BLAKE2b-256 of the raw FVK, broadcast in the ceremony's confirmation
    /// round so every participant can check it derived the same account.
    pub fn fvk_hash(&self) -> [u8; 32] {
        crate::ceremony::fvk_hash(&self.fvk.to_bytes())
    }
}
