//! Address generation from the external incoming viewing key.
//!
//! An address server holds only the account's external Orchard-protocol IVK
//! and mints shielded-only unified addresses (one Orchard receiver; payments
//! to it land in the Ironwood pool). Every address uses a fresh diversifier
//! index, so payers cannot link two addresses of the same account.
//!
//! Several servers can run without coordinating: server `i` owns the
//! diversifier indices whose top byte (of the 88-bit, little-endian index) is
//! `i`, leaving 2^80 indices each. A server must persist its counter (or the
//! highest index it issued) so it never reissues an index after a restart.
//!
//! Detectors find payments to every one of these addresses with the same IVK;
//! no per-address registration is needed.

use orchard::keys::{DiversifierIndex, IncomingViewingKey};
use zcash_address::unified::{self, Encoding};
use zcash_protocol::consensus::NetworkType;

/// Address generation errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// This server's 2^80 indices are used up.
    #[error("diversifier range for server {0} exhausted")]
    Exhausted(u8),
    /// Unified address encoding failed.
    #[error("unified address encoding: {0}")]
    Encoding(String),
}

/// A minted address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedAddress {
    /// Bech32m unified address.
    pub unified_address: String,
    /// The raw 43-byte Orchard receiver.
    pub orchard_receiver: [u8; 43],
    /// 11-byte little-endian diversifier index.
    pub diversifier_index: [u8; 11],
}

/// Number of indices each server owns.
pub const INDICES_PER_SERVER: u128 = 1 << 80;

/// The diversifier index for a server's `counter`-th address.
pub fn diversifier_index(server_id: u8, counter: u128) -> Result<[u8; 11], Error> {
    if counter >= INDICES_PER_SERVER {
        return Err(Error::Exhausted(server_id));
    }
    let mut out = [0u8; 11];
    out[..10].copy_from_slice(&counter.to_le_bytes()[..10]);
    out[10] = server_id;
    Ok(out)
}

/// Mints addresses for one account from one server's index range.
pub struct AddressServer {
    ivk: IncomingViewingKey,
    network: NetworkType,
    server_id: u8,
    next: u128,
}

impl AddressServer {
    /// A server for `ivk` (the account's external IVK), resuming at `next`
    /// (the persisted count of addresses already issued).
    pub fn new(ivk: IncomingViewingKey, network: NetworkType, server_id: u8, next: u128) -> Self {
        AddressServer {
            ivk,
            network,
            server_id,
            next,
        }
    }

    /// This server's id.
    pub fn server_id(&self) -> u8 {
        self.server_id
    }

    /// How many addresses this server has issued; persist it after each call.
    pub fn issued(&self) -> u128 {
        self.next
    }

    /// The address at a specific index (for example to re-derive one a
    /// customer asks about). Does not change the counter.
    pub fn address_at(&self, diversifier_index: [u8; 11]) -> Result<IssuedAddress, Error> {
        let addr = self
            .ivk
            .address_at(DiversifierIndex::from(diversifier_index));
        let raw = addr.to_raw_address_bytes();
        // Revision 0 (`u1...`) is what deployed wallets parse today.
        let ua = unified::Address::try_from_items(
            unified::Revision::R0,
            vec![unified::Uitem::Data(unified::Receiver::Orchard(raw))],
        )
        .map_err(|e| Error::Encoding(e.to_string()))?;
        Ok(IssuedAddress {
            unified_address: ua.encode(&self.network),
            orchard_receiver: raw,
            diversifier_index,
        })
    }

    /// Mints the next address.
    pub fn next_address(&mut self) -> Result<IssuedAddress, Error> {
        let idx = diversifier_index(self.server_id, self.next)?;
        let a = self.address_at(idx)?;
        self.next += 1;
        Ok(a)
    }
}

/// Unified key encodings and the account fingerprint used on the wire.
pub mod keys {
    use orchard::keys::{FullViewingKey, IncomingViewingKey, Scope};
    use zcash_address::unified::{self, Container, Encoding};
    use zcash_protocol::consensus::NetworkType;

    /// Encodes the account's UFVK (Orchard item only).
    pub fn ufvk(fvk: &FullViewingKey, network: NetworkType) -> String {
        unified::Ufvk::try_from_items(
            unified::Revision::R0,
            vec![unified::Uitem::Data(unified::Fvk::Orchard(fvk.to_bytes()))],
        )
        .expect("one Orchard item is a valid UFVK")
        .encode(&network)
    }

    /// Encodes the account's UIVK (external Orchard IVK only).
    pub fn uivk(fvk: &FullViewingKey, network: NetworkType) -> String {
        let ivk = fvk.to_ivk(Scope::External).to_bytes();
        unified::Uivk::try_from_items(
            unified::Revision::R0,
            vec![unified::Uitem::Data(unified::Ivk::Orchard(ivk))],
        )
        .expect("one Orchard item is a valid UIVK")
        .encode(&network)
    }

    /// Decodes a UFVK's Orchard FVK.
    pub fn parse_ufvk(s: &str) -> Option<(NetworkType, FullViewingKey)> {
        let (net, _, ufvk) = unified::Ufvk::decode(s).ok()?;
        ufvk.items().into_iter().find_map(|i| match i {
            unified::Fvk::Orchard(b) => FullViewingKey::from_bytes(&b).map(|f| (net, f)),
            _ => None,
        })
    }

    /// Decodes a UIVK's Orchard (external) IVK.
    pub fn parse_uivk(s: &str) -> Option<(NetworkType, IncomingViewingKey)> {
        let (net, _, uivk) = unified::Uivk::decode(s).ok()?;
        uivk.items().into_iter().find_map(|i| match i {
            unified::Ivk::Orchard(b) => {
                Option::from(IncomingViewingKey::from_bytes(&b)).map(|k| (net, k))
            }
            _ => None,
        })
    }

    /// `AccountRef.ufvk_fingerprint`: BLAKE2b-256 of the encoded UFVK.
    pub fn fingerprint(ufvk: &str) -> [u8; 32] {
        let h = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"ZDisagg_UfvkFp__")
            .hash(ufvk.as_bytes());
        h.as_bytes().try_into().expect("32 bytes")
    }

    /// Parses a payment address: a unified address with an Orchard receiver,
    /// or 43 raw Orchard address bytes in hex.
    pub fn parse_orchard_address(s: &str) -> Option<orchard::Address> {
        let raw: [u8; 43] = if let Ok((_, _, ua)) = unified::Address::decode(s) {
            ua.items().into_iter().find_map(|r| match r {
                unified::Receiver::Orchard(b) => Some(b),
                _ => None,
            })?
        } else {
            let bytes: Vec<u8> = (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
                .collect::<Option<_>>()?;
            bytes.try_into().ok()?
        };
        Option::from(orchard::Address::from_raw_address_bytes(&raw))
    }
}
