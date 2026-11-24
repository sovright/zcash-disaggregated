//! The 1/1 Signer service. A FROST quorum's coordinator implements the same
//! RPC but drives the signing rounds; see `zd_pczt::frost`.

use std::collections::HashMap;

use orchard::primitives::redpallas::{SigningKey, SpendAuth};
use pczt::Pczt;
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use tonic::{Request, Response, Status};
use zd_pczt::SigningRequest;
use zd_proto::v1::{SignJob, SignResult, sign_result::Outcome, signer_server::Signer};

/// Decides whether to sign. Runs after the PCZT has been parsed and the
/// account's spends found, before any signature exists. This is where a
/// deployment checks recipients, amounts, rate limits and approvals (using
/// the PCZT Verifier role on `pczt`).
pub trait Policy: Send + Sync + 'static {
    /// `Err(reason)` rejects the job; the reason goes back to the caller.
    fn check(&self, job: &SignJob, pczt: &Pczt, request: &SigningRequest) -> Result<(), String>;
}

/// Signs anything that spends the account. For tests only.
pub struct AllowAll;

impl Policy for AllowAll {
    fn check(&self, _: &SignJob, _: &Pczt, _: &SigningRequest) -> Result<(), String> {
        Ok(())
    }
}

/// One account this signer holds `ask` for.
pub struct SignerAccount {
    /// `ak` (32 bytes, ỹ = 0).
    pub ak: [u8; 32],
    /// `ask`, already normalized so that `[ask] G = ak`.
    pub ask: SigningKey<SpendAuth>,
}

/// A 1/1 signer for one or more accounts.
pub struct SingleSignerService<P> {
    accounts: HashMap<Vec<u8>, SignerAccount>,
    policy: P,
}

impl<P: Policy> SingleSignerService<P> {
    /// `accounts` is keyed by UFVK fingerprint.
    pub fn new(accounts: HashMap<Vec<u8>, SignerAccount>, policy: P) -> Self {
        SingleSignerService { accounts, policy }
    }
}

#[tonic::async_trait]
impl<P: Policy> Signer for SingleSignerService<P> {
    async fn sign(&self, request: Request<SignJob>) -> Result<Response<SignResult>, Status> {
        let job = request.into_inner();
        let fp = crate::fingerprint(&job.account)?;
        let account = self.accounts.get(&fp).ok_or_else(|| {
            Status::not_found(format!("no signing key for account {}", crate::fp_hex(&fp)))
        })?;

        let reject = |reason: String| {
            Ok(Response::new(SignResult {
                job_id: job.job_id.clone(),
                outcome: Some(Outcome::RejectedReason(reason)),
            }))
        };

        let pczt = match Pczt::parse(&job.pczt) {
            Ok(p) => p,
            Err(e) => return reject(format!("parse: {e:?}")),
        };
        let req = match zd_pczt::signing_request(&pczt, &account.ak) {
            Ok(r) => r,
            Err(e) => return reject(e.to_string()),
        };
        if let Err(reason) = self.policy.check(&job, &pczt, &req) {
            return reject(format!("policy: {reason}"));
        }

        let sigs = zd_pczt::sign_with_ask(&req, &account.ask, &mut UnwrapErr(SysRng));
        let signed = zd_pczt::apply_signatures(pczt, &sigs).and_then(|p| {
            p.serialize()
                .map_err(|e| zd_pczt::Error::Pczt(format!("{e:?}")))
        });
        match signed {
            Ok(bytes) => Ok(Response::new(SignResult {
                job_id: job.job_id,
                outcome: Some(Outcome::SignedPczt(bytes)),
            })),
            Err(e) => reject(e.to_string()),
        }
    }
}
