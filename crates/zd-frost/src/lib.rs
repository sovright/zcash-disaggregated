//! FROST(Pallas, BLAKE2b-512): threshold RedPallas spend authorization for
//! Orchard-protocol (Ironwood / Orchard) accounts.
//!
//! The ciphersuite in this module is a port of the one `reddsa` 0.5.2 shipped
//! behind its `frost` feature, which `reddsa` 0.6 removed and which has not yet
//! been republished from the ZcashFoundation `frost` repository. It is moved
//! onto `pasta_curves` 0.6 (the version `orchard` 0.16 uses) and keeps every
//! upstream constant: the ciphersuite ID, hash personalizations, generator and
//! encodings. Key packages, commitments, signature shares and signatures are
//! therefore byte-identical to upstream (the tests check this against
//! `reddsa` 0.5.2), so we can switch to the upstream crate when it lands.
//!
//! On top of the ciphersuite:
//!
//! - [`spend`] signs with the randomizer `alpha` that a PCZT already fixes for
//!   each Orchard spend, instead of one the FROST coordinator derives.
//! - [`ceremony`] runs the FROST DKG together with the commit-reveal shared
//!   `sk` from `zd_keys`, and returns the ZIP 2005 quantum-recoverable account.
//!
//! Portions derived from `reddsa` (Copyright (c) 2019-2021 Zcash Foundation),
//! used under the MIT license.

#![allow(non_snake_case)]
#![deny(missing_docs)]

use std::collections::BTreeMap;

use ff::{FromUniformBytes, PrimeField};
use group::{Group as _, GroupEncoding};
use pasta_curves::pallas;

pub use frost_rerandomized::frost_core::{Ciphersuite, Field, FieldError, Group, GroupError};
pub use frost_rerandomized::{self, RandomizedCiphersuite, frost_core as frost};
pub use rand_core;

use rand_core::{CryptoRng, RngCore};

pub mod ceremony;
pub mod spend;

/// An error from the FROST(Pallas, BLAKE2b-512) ciphersuite.
pub type Error = frost::Error<PallasBlake2b512>;

/// Encoding of the Orchard `SpendAuthSig` basepoint,
/// `GroupHash^P("z.cash:Orchard", "G")`.
pub const SPENDAUTH_BASEPOINT_BYTES: [u8; 32] = [
    99, 201, 117, 184, 132, 114, 26, 141, 12, 161, 112, 123, 227, 12, 127, 12, 95, 68, 95, 62, 124,
    24, 141, 59, 6, 214, 241, 40, 179, 35, 85, 183,
];

/// `H^star` with a given personalization: BLAKE2b-512, reduced mod r_P.
fn h_star(personal: &[u8; 16], m: &[u8]) -> pallas::Scalar {
    let h = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(personal)
        .hash(m);
    pallas::Scalar::from_uniform_bytes(h.as_array())
}

fn h_512(personal: &[u8; 16], m: &[u8]) -> [u8; 64] {
    *blake2b_simd::Params::new()
        .hash_length(64)
        .personal(personal)
        .hash(m)
        .as_array()
}

/// The Pallas scalar field.
#[derive(Clone, Copy)]
pub struct PallasScalarField;

impl Field for PallasScalarField {
    type Scalar = pallas::Scalar;
    type Serialization = [u8; 32];

    fn zero() -> Self::Scalar {
        pallas::Scalar::zero()
    }

    fn one() -> Self::Scalar {
        pallas::Scalar::one()
    }

    fn invert(scalar: &Self::Scalar) -> Result<Self::Scalar, FieldError> {
        Option::from(ff::Field::invert(scalar)).ok_or(FieldError::InvalidZeroScalar)
    }

    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        // Same construction as pasta_curves' `Field::random`, which we cannot
        // call directly because it takes a rand_core 0.10 RNG.
        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        let s = pallas::Scalar::from_uniform_bytes(&buf);
        zeroize::Zeroize::zeroize(&mut buf);
        s
    }

    fn serialize(scalar: &Self::Scalar) -> Self::Serialization {
        scalar.to_repr()
    }

    fn little_endian_serialize(scalar: &Self::Scalar) -> Self::Serialization {
        scalar.to_repr()
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Scalar, FieldError> {
        Option::from(pallas::Scalar::from_repr(*buf)).ok_or(FieldError::MalformedScalar)
    }
}

/// The Pallas group, with the Orchard `SpendAuthSig` basepoint as generator.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PallasGroup;

impl Group for PallasGroup {
    type Field = PallasScalarField;
    type Element = pallas::Point;
    type Serialization = [u8; 32];

    fn cofactor() -> pallas::Scalar {
        pallas::Scalar::one()
    }

    fn identity() -> Self::Element {
        pallas::Point::identity()
    }

    fn generator() -> Self::Element {
        pallas::Point::from_bytes(&SPENDAUTH_BASEPOINT_BYTES).unwrap()
    }

    fn serialize(element: &Self::Element) -> Result<Self::Serialization, GroupError> {
        if bool::from(element.is_identity()) {
            return Err(GroupError::InvalidIdentityElement);
        }
        Ok(element.to_bytes())
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, GroupError> {
        let point: pallas::Point =
            Option::from(pallas::Point::from_bytes(buf)).ok_or(GroupError::MalformedElement)?;
        if bool::from(point.is_identity()) {
            Err(GroupError::InvalidIdentityElement)
        } else {
            Ok(point)
        }
    }
}

/// The FROST(Pallas, BLAKE2b-512) ciphersuite. Its signatures are Orchard
/// `SpendAuthSig` RedPallas signatures.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PallasBlake2b512;

impl Ciphersuite for PallasBlake2b512 {
    const ID: &'static str = "FROST(Pallas, BLAKE2b-512)";

    type Group = PallasGroup;
    type HashOutput = [u8; 64];
    type SignatureSerialization = [u8; 64];

    fn H1(m: &[u8]) -> pallas::Scalar {
        h_star(b"FROST_RedPallasR", m)
    }

    /// The RedPallas challenge hash, so aggregate signatures verify as
    /// ordinary `SpendAuthSig`s.
    fn H2(m: &[u8]) -> pallas::Scalar {
        h_star(b"Zcash_RedPallasH", m)
    }

    fn H3(m: &[u8]) -> pallas::Scalar {
        h_star(b"FROST_RedPallasN", m)
    }

    fn H4(m: &[u8]) -> [u8; 64] {
        h_512(b"FROST_RedPallasM", m)
    }

    fn H5(m: &[u8]) -> [u8; 64] {
        h_512(b"FROST_RedPallasC", m)
    }

    fn HDKG(m: &[u8]) -> Option<pallas::Scalar> {
        Some(h_star(b"FROST_RedPallasD", m))
    }

    fn HID(m: &[u8]) -> Option<pallas::Scalar> {
        Some(h_star(b"FROST_RedPallasI", m))
    }

    fn post_generate(
        secret_shares: BTreeMap<Identifier, keys::SecretShare>,
        public_key_package: keys::PublicKeyPackage,
    ) -> Result<
        (
            BTreeMap<Identifier, keys::SecretShare>,
            keys::PublicKeyPackage,
        ),
        Error,
    > {
        Ok(keys::into_even_y((secret_shares, public_key_package)))
    }

    fn post_dkg(
        key_package: keys::KeyPackage,
        public_key_package: keys::PublicKeyPackage,
    ) -> Result<(keys::KeyPackage, keys::PublicKeyPackage), Error> {
        use keys::EvenY;
        let is_even = public_key_package.has_even_y();
        Ok((
            key_package.into_even_y(Some(is_even)),
            public_key_package.into_even_y(Some(is_even)),
        ))
    }
}

impl RandomizedCiphersuite for PallasBlake2b512 {
    fn hash_randomizer(m: &[u8]) -> Option<pallas::Scalar> {
        Some(h_star(b"FROST_RedPallasA", m))
    }
}

type P = PallasBlake2b512;

/// A participant identifier.
pub type Identifier = frost::Identifier<P>;
/// A generic FROST signing package: the message and every signer's commitments.
pub type SigningPackage = frost::SigningPackage<P>;
/// An aggregate signature, encoded as a 64-byte RedPallas `SpendAuthSig`.
pub type Signature = frost::Signature<P>;
/// A single-party signing key.
pub type SigningKey = frost::SigningKey<P>;
/// A group (or randomized group) verifying key, encoded as `ak` (or `rk`).
pub type VerifyingKey = frost::VerifyingKey<P>;

/// Key generation and key share types.
pub mod keys {
    use super::*;

    /// Identifiers to use when generating key shares with a dealer.
    pub type IdentifierList<'a> = frost::keys::IdentifierList<'a, P>;
    /// A share sent by a trusted dealer.
    pub type SecretShare = frost::keys::SecretShare<P>;
    /// A participant's secret share of the group key.
    pub type SigningShare = frost::keys::SigningShare<P>;
    /// A participant's public verification share.
    pub type VerifyingShare = frost::keys::VerifyingShare<P>;
    /// A participant's long-lived key material.
    pub type KeyPackage = frost::keys::KeyPackage<P>;
    /// Every participant's verifying share plus the group key.
    pub type PublicKeyPackage = frost::keys::PublicKeyPackage<P>;
    /// Commitments to a participant's secret polynomial.
    pub type VerifiableSecretSharingCommitment = frost::keys::VerifiableSecretSharingCommitment<P>;

    /// Trusted-dealer key generation. For tests and for importing an HSM key;
    /// production quorums use [`crate::ceremony`].
    pub fn generate_with_dealer<R: RngCore + CryptoRng>(
        max_signers: u16,
        min_signers: u16,
        identifiers: IdentifierList,
        rng: &mut R,
    ) -> Result<(BTreeMap<Identifier, SecretShare>, PublicKeyPackage), Error> {
        frost::keys::generate_with_dealer(max_signers, min_signers, identifiers, rng)
    }

    /// Splits an existing `ask` into shares. The group key is negated if
    /// needed so that ỹ(ak) = 0.
    pub fn split<R: RngCore + CryptoRng>(
        key: &SigningKey,
        max_signers: u16,
        min_signers: u16,
        identifiers: IdentifierList,
        rng: &mut R,
    ) -> Result<(BTreeMap<Identifier, SecretShare>, PublicKeyPackage), Error> {
        frost::keys::split(key, max_signers, min_signers, identifiers, rng)
    }

    /// Normalizes a group key so its encoding has ỹ = 0, as Orchard requires
    /// of `ak`.
    ///
    /// Negating the group secret negates every share (Shamir sharing is
    /// linear), so each participant can do this locally. The DKG and dealer
    /// paths already call it through the ciphersuite's post-processing hooks.
    pub trait EvenY {
        /// Whether the group key's encoding has ỹ = 0.
        fn has_even_y(&self) -> bool;
        /// Negates everything if the group key has ỹ = 1. Pass `is_even` if
        /// already known.
        fn into_even_y(self, is_even: Option<bool>) -> Self;
    }

    fn vk_is_even(vk: &VerifyingKey) -> bool {
        match vk.serialize() {
            Ok(b) => b[31] & 0x80 == 0,
            Err(_) => true,
        }
    }

    impl EvenY for PublicKeyPackage {
        fn has_even_y(&self) -> bool {
            vk_is_even(self.verifying_key())
        }

        fn into_even_y(self, is_even: Option<bool>) -> Self {
            if is_even.unwrap_or_else(|| self.has_even_y()) {
                return self;
            }
            let verifying_key = VerifyingKey::new(-self.verifying_key().to_element());
            let verifying_shares = self
                .verifying_shares()
                .iter()
                .map(|(i, vs)| (*i, VerifyingShare::new(-vs.to_element())))
                .collect();
            PublicKeyPackage::new(verifying_shares, verifying_key, self.min_signers())
        }
    }

    impl EvenY for SecretShare {
        fn has_even_y(&self) -> bool {
            let key_package: KeyPackage = self
                .clone()
                .try_into()
                .expect("called on freshly generated SecretShares");
            key_package.has_even_y()
        }

        fn into_even_y(self, is_even: Option<bool>) -> Self {
            if is_even.unwrap_or_else(|| self.has_even_y()) {
                return self;
            }
            let signing_share = SigningShare::new(-self.signing_share().to_scalar());
            let coefficients: Vec<_> = self
                .commitment()
                .coefficients()
                .iter()
                .map(|e| {
                    PallasGroup::serialize(&-e.value())
                        .expect("coefficient commitments are never the identity")
                })
                .collect();
            let commitment = VerifiableSecretSharingCommitment::deserialize(coefficients)
                .expect("just serialized");
            SecretShare::new(*self.identifier(), signing_share, commitment)
        }
    }

    impl EvenY for KeyPackage {
        fn has_even_y(&self) -> bool {
            vk_is_even(self.verifying_key())
        }

        fn into_even_y(self, is_even: Option<bool>) -> Self {
            if is_even.unwrap_or_else(|| self.has_even_y()) {
                return self;
            }
            KeyPackage::new(
                *self.identifier(),
                SigningShare::new(-self.signing_share().to_scalar()),
                VerifyingShare::new(-self.verifying_share().to_element()),
                VerifyingKey::new(-self.verifying_key().to_element()),
                *self.min_signers(),
            )
        }
    }

    pub(crate) fn into_even_y(
        (secret_shares, public_key_package): (BTreeMap<Identifier, SecretShare>, PublicKeyPackage),
    ) -> (BTreeMap<Identifier, SecretShare>, PublicKeyPackage) {
        let is_even = public_key_package.has_even_y();
        let public_key_package = public_key_package.into_even_y(Some(is_even));
        let secret_shares = secret_shares
            .into_iter()
            .map(|(i, s)| (i, s.into_even_y(Some(is_even))))
            .collect();
        (secret_shares, public_key_package)
    }

    /// Distributed key generation (no dealer). [`crate::ceremony`] wraps
    /// these with the shared `sk` rounds.
    pub mod dkg {
        use super::*;

        /// DKG round 1 types.
        pub mod round1 {
            use super::*;
            /// Kept by the participant between part 1 and part 2. Never sent.
            pub type SecretPackage = frost::keys::dkg::round1::SecretPackage<P>;
            /// Broadcast to every other participant.
            pub type Package = frost::keys::dkg::round1::Package<P>;
        }

        /// DKG round 2 types.
        pub mod round2 {
            use super::*;
            /// Kept by the participant between part 2 and part 3. Never sent.
            pub type SecretPackage = frost::keys::dkg::round2::SecretPackage<P>;
            /// Sent to one recipient over a confidential, authenticated channel.
            pub type Package = frost::keys::dkg::round2::Package<P>;
        }

        /// DKG part 1.
        pub fn part1<R: RngCore + CryptoRng>(
            identifier: Identifier,
            max_signers: u16,
            min_signers: u16,
            rng: &mut R,
        ) -> Result<(round1::SecretPackage, round1::Package), Error> {
            frost::keys::dkg::part1(identifier, max_signers, min_signers, rng)
        }

        /// DKG part 2.
        #[allow(clippy::type_complexity)]
        pub fn part2(
            secret_package: round1::SecretPackage,
            round1_packages: &BTreeMap<Identifier, round1::Package>,
        ) -> Result<(round2::SecretPackage, BTreeMap<Identifier, round2::Package>), Error> {
            frost::keys::dkg::part2(secret_package, round1_packages)
        }

        /// DKG part 3. The result already has ỹ(ak) = 0.
        pub fn part3(
            round2_secret_package: &round2::SecretPackage,
            round1_packages: &BTreeMap<Identifier, round1::Package>,
            round2_packages: &BTreeMap<Identifier, round2::Package>,
        ) -> Result<(KeyPackage, PublicKeyPackage), Error> {
            frost::keys::dkg::part3(round2_secret_package, round1_packages, round2_packages)
        }
    }
}

/// Signing round 1 (commitments).
pub mod round1 {
    use super::*;
    /// One-time nonces. Never reuse.
    pub type SigningNonces = frost::round1::SigningNonces<P>;
    /// Commitments to a participant's nonces, sent to the coordinator.
    pub type SigningCommitments = frost::round1::SigningCommitments<P>;
}

/// Signing round 2 (shares).
pub mod round2 {
    use super::*;
    /// A participant's signature share.
    pub type SignatureShare = frost::round2::SignatureShare<P>;
}
