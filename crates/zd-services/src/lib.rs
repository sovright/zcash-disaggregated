//! gRPC services for the wallet roles:
//!
//! - [`prover::ProverService`]: any 1 of n provers. Proving runs on a
//!   blocking thread with bounded concurrency.
//! - [`signer::SingleSignerService`]: a 1/1 signer holding `ask` (for
//!   example in an HSM) with a pluggable [`signer::Policy`].
//! - [`frost::FrostParticipantService`] and [`frost::FrostCoordinatorService`]:
//!   a FROST quorum over our own gRPC rounds; the coordinator is the account's
//!   `Signer` service.
//! - [`address::AddressServiceImpl`]: diversified address minting with a
//!   persisted counter per account.
//!
//! Accounts are identified on the wire by `AccountRef.ufvk_fingerprint`.

pub mod address;
pub mod frost;
pub mod prover;
pub mod signer;

/// Hex of an account fingerprint, for error messages and logs.
pub(crate) fn fp_hex(fp: &[u8]) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn fingerprint(
    account: &Option<zd_proto::v1::AccountRef>,
) -> Result<Vec<u8>, tonic::Status> {
    match account {
        Some(a) if a.ufvk_fingerprint.len() == 32 => Ok(a.ufvk_fingerprint.clone()),
        _ => Err(tonic::Status::invalid_argument(
            "account.ufvk_fingerprint must be 32 bytes",
        )),
    }
}
