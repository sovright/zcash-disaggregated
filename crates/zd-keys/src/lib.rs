//! Key derivation for disaggregated Orchard-protocol (Ironwood / Orchard)
//! accounts whose spend authorizing key `ask` is never held in one place:
//! FROST t-of-n quorums and HSM-held 1/1 signers.
//!
//! Every account this crate builds uses the [ZIP 2005] `use_qsk = true` key
//! path, so Ironwood notes it receives stay quantum-recoverable:
//!
//! ```text
//! nk       = ToBase(PRF_expand_sk([0x07]))
//! qsk      = truncate_32(PRF_expand_sk([0x0C]))
//! qk       = BLAKE3.derive_key("Zcash ZIP 2005 qk-derivation v1", qsk)
//! rivk_ext = ToScalar(PRF_expand_qk([0x0D] || I2LEOSP_256(ak) || I2LEOSP_256(nk)))
//! ak       from FROST DKG or an HSM-generated ask, with ỹ(ak) = 0
//! ```
//!
//! `sk` here is a 32-byte secret shared by every participant (see
//! [`ceremony`]). It yields `nk` and `qsk` but never `ask`.
//!
//! [ZIP 2005]: https://zips.z.cash/zip-2005

pub mod account;
pub mod ceremony;
pub mod zip2005;

pub use account::{AccountKeys, Error};
pub use zip2005::{Qk, Qsk};
