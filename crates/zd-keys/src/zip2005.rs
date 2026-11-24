//! The ZIP 2005 / protocol spec § 4.2.3 key derivation functions.

use blake2b_simd::Params;
use ff::{Field, FromUniformBytes, PrimeField};
use pasta_curves::pallas;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// BLAKE3 `derive_key` context for `H^qk` (ZIP 2005).
pub const QK_CONTEXT: &str = "Zcash ZIP 2005 qk-derivation v1";

/// `PRF^expand_key(t) = BLAKE2b-512("Zcash_ExpandSeed", key || t)`.
pub fn prf_expand(key: &[u8; 32], t: &[&[u8]]) -> [u8; 64] {
    let mut h = Params::new()
        .hash_length(64)
        .personal(b"Zcash_ExpandSeed")
        .to_state();
    h.update(key);
    for part in t {
        h.update(part);
    }
    *h.finalize().as_array()
}

/// `ToBase^Orchard`: interpret 64 bytes little-endian and reduce mod q_P.
pub fn to_base(x: [u8; 64]) -> pallas::Base {
    pallas::Base::from_uniform_bytes(&x)
}

/// `ToScalar^Orchard`: interpret 64 bytes little-endian and reduce mod r_P.
pub fn to_scalar(x: [u8; 64]) -> pallas::Scalar {
    pallas::Scalar::from_uniform_bytes(&x)
}

/// The quantum spending key. Every FROST participant holds it; per ZIP 2005 it
/// must be stored at least as securely as an `ask` share.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Qsk([u8; 32]);

impl Qsk {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Qsk(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The quantum intermediate key, `H^qk(qsk)`. Semi-sensitive: wallet state
/// (ZIP 2005's "host wallet") holds it for the future recovery statement.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Qk([u8; 32]);

impl Qk {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Qk(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for Qk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Qk(..)")
    }
}

/// `H^nk(sk) = ToBase(PRF_expand_sk([0x07]))`.
pub fn nk(sk: &[u8; 32]) -> pallas::Base {
    to_base(prf_expand(sk, &[&[0x07]]))
}

/// `H^qsk(sk) = truncate_32(PRF_expand_sk([0x0C]))`.
pub fn qsk(sk: &[u8; 32]) -> Qsk {
    let mut out = prf_expand(sk, &[&[0x0C]]);
    let mut q = [0u8; 32];
    q.copy_from_slice(&out[..32]);
    out.zeroize();
    Qsk(q)
}

/// `H^qk(qsk) = BLAKE3.derive_key("Zcash ZIP 2005 qk-derivation v1", qsk, 32)`.
pub fn qk(qsk: &Qsk) -> Qk {
    Qk(blake3::derive_key(QK_CONTEXT, &qsk.0))
}

/// `H^rivk_ext_qk(ak, nk) = ToScalar(PRF_expand_qk([0x0D] || I2LEOSP_256(ak) || I2LEOSP_256(nk)))`.
///
/// `ak` is the 32-byte encoding of the spend validating key. With ỹ = 0 (which
/// [`crate::AccountKeys`] enforces) it equals `I2LEOSP_256` of the x-coordinate.
pub fn rivk_ext(qk: &Qk, ak: &[u8; 32], nk: &pallas::Base) -> pallas::Scalar {
    to_scalar(prf_expand(&qk.0, &[&[0x0D], ak, &nk.to_repr()]))
}

/// Legacy (`use_qsk = false`) `H^ask(sk) = ToScalar(PRF_expand_sk([0x06]))`,
/// before sign normalization. Used only to cross-check against `orchard`.
pub fn legacy_ask(sk: &[u8; 32]) -> pallas::Scalar {
    to_scalar(prf_expand(sk, &[&[0x06]]))
}

/// Legacy (`use_qsk = false`) `H^rivk(sk) = ToScalar(PRF_expand_sk([0x08]))`.
pub fn legacy_rivk(sk: &[u8; 32]) -> pallas::Scalar {
    to_scalar(prf_expand(sk, &[&[0x08]]))
}

/// Returns `ask` or `-ask`, whichever gives a spend validating key whose
/// encoding has ỹ = 0, plus that encoding. Returns `None` for `ask = 0`.
///
/// A FROST group does the same thing by having every participant negate its
/// share (and the group key) when ỹ(ak) = 1.
pub fn normalize_ask(ask: pallas::Scalar) -> Option<(pallas::Scalar, [u8; 32])> {
    use orchard::primitives::redpallas::{SigningKey, SpendAuth, VerificationKey};
    if bool::from(ask.is_zero()) {
        return None;
    }
    let ak_bytes = |s: pallas::Scalar| -> Option<[u8; 32]> {
        let sk = SigningKey::<SpendAuth>::try_from(s.to_repr()).ok()?;
        Some((&VerificationKey::from(&sk)).into())
    };
    let ak = ak_bytes(ask)?;
    if ak[31] & 0x80 == 0 {
        Some((ask, ak))
    } else {
        let neg = -ask;
        let ak = ak_bytes(neg)?;
        debug_assert_eq!(ak[31] & 0x80, 0);
        Some((neg, ak))
    }
}
