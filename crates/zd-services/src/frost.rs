//! A FROST quorum over our own gRPC rounds.
//!
//! - Each member runs [`FrostParticipantService`] with its key share.
//! - The account's [`FrostCoordinatorService`] implements the ordinary
//!   `Signer` RPC that wallet state calls. It asks every member to commit,
//!   picks `threshold` of the members that agreed, asks exactly those to sign,
//!   aggregates, and returns the signed PCZT.
//!
//! Members check the PCZT and run their own [`Policy`] before creating any
//! nonce, and bind the nonces to the PCZT's sighash and each spend's alpha
//! (`zd_frost::spend`). The coordinator holds no secret: a malicious one can
//! refuse service or waste nonces, but cannot obtain a signature over anything
//! a member did not approve.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use pczt::Pczt;
use rand_core_06::OsRng;
use tokio::task::JoinSet;
use tonic::transport::Channel;
use tonic::{Request, Response, Status};
use zd_frost::{
    Identifier, SigningPackage,
    keys::{KeyPackage, PublicKeyPackage},
    round1::SigningCommitments,
    round2::SignatureShare,
    spend::BoundNonces,
};
use zd_pczt::SigningRequest;
use zd_proto::v1::{
    AccountRef, FrostCommitRequest, FrostCommitResponse, FrostCommitments, FrostShares,
    FrostSignRequest, FrostSignResponse, SignJob, SignResult, frost_commit_response,
    frost_participant_client::FrostParticipantClient, frost_participant_server::FrostParticipant,
    frost_sign_response, sign_result, signer_server::Signer,
};

use crate::signer::Policy;

/// Digest of the sighash that members return so the coordinator can check
/// they all see the same transaction.
pub fn sighash_digest(sighash: &[u8; 32]) -> Vec<u8> {
    blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"ZDisagg_Sighash_")
        .hash(sighash)
        .as_bytes()
        .to_vec()
}

/// (account fingerprint, job id).
type JobKey = (Vec<u8>, Vec<u8>);

struct Pending {
    nonces: Vec<BoundNonces>,
}

/// Most jobs a member keeps nonces for at once. Committing to a new job when
/// full is refused, which bounds what a coordinator that never calls Sign can
/// make a member hold.
pub const MAX_PENDING_JOBS: usize = 1024;

/// One quorum member.
pub struct FrostParticipantService<P> {
    accounts: HashMap<Vec<u8>, KeyPackage>,
    policy: P,
    pending: Mutex<HashMap<JobKey, Pending>>,
}

impl<P: Policy> FrostParticipantService<P> {
    /// `accounts` maps UFVK fingerprint to this member's key package.
    pub fn new(accounts: HashMap<Vec<u8>, KeyPackage>, policy: P) -> Self {
        FrostParticipantService {
            accounts,
            policy,
            pending: Mutex::new(HashMap::new()),
        }
    }

    fn key(&self, account: &Option<AccountRef>) -> Result<(Vec<u8>, &KeyPackage), Status> {
        let fp = crate::fingerprint(account)?;
        let kp = self.accounts.get(&fp).ok_or_else(|| {
            Status::not_found(format!("no key share for account {}", crate::fp_hex(&fp)))
        })?;
        Ok((fp, kp))
    }
}

fn ak_of(pkp_vk: &zd_frost::VerifyingKey) -> Result<[u8; 32], Status> {
    pkp_vk
        .serialize()
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| Status::internal("group key does not serialize"))
}

#[tonic::async_trait]
impl<P: Policy> FrostParticipant for FrostParticipantService<P> {
    async fn commit(
        &self,
        request: Request<FrostCommitRequest>,
    ) -> Result<Response<FrostCommitResponse>, Status> {
        let req = request.into_inner();
        let (fp, kp) = self.key(&req.account)?;
        let identifier = kp.identifier().serialize();
        let reply = |outcome| {
            Ok(Response::new(FrostCommitResponse {
                job_id: req.job_id.clone(),
                identifier: identifier.clone(),
                outcome: Some(outcome),
            }))
        };
        let reject = |r: String| reply(frost_commit_response::Outcome::RejectedReason(r));

        let pczt = match Pczt::parse(&req.pczt) {
            Ok(p) => p,
            Err(e) => return reject(format!("parse: {e:?}")),
        };
        let signing = match zd_pczt::signing_request(&pczt, &ak_of(kp.verifying_key())?) {
            Ok(r) => r,
            Err(e) => return reject(e.to_string()),
        };
        let job = SignJob {
            job_id: req.job_id.clone(),
            account: req.account.clone(),
            pczt: Vec::new(),
            memo: req.memo.clone(),
        };
        if let Err(r) = self.policy.check(&job, &pczt, &signing) {
            return reject(format!("policy: {r}"));
        }

        let (nonces, commitments) = zd_pczt::frost::commit(kp, &signing, &mut OsRng);
        let mut per_spend = Vec::with_capacity(commitments.len());
        for c in &commitments {
            per_spend.push(
                c.serialize()
                    .map_err(|e| Status::internal(format!("commitments: {e}")))?,
            );
        }
        {
            let mut pending = self.pending.lock().unwrap();
            let key = (fp, req.job_id.clone());
            if pending.contains_key(&key) {
                return reject("already committed to this job".into());
            }
            if pending.len() >= MAX_PENDING_JOBS {
                return reject("too many jobs in flight".into());
            }
            pending.insert(key, Pending { nonces });
        }
        reply(frost_commit_response::Outcome::Commitments(
            FrostCommitments {
                per_spend,
                sighash_digest: sighash_digest(&signing.sighash),
            },
        ))
    }

    async fn sign(
        &self,
        request: Request<FrostSignRequest>,
    ) -> Result<Response<FrostSignResponse>, Status> {
        let req = request.into_inner();
        let (fp, kp) = self.key(&req.account)?;
        let reject = |r: String| {
            Ok(Response::new(FrostSignResponse {
                job_id: req.job_id.clone(),
                outcome: Some(frost_sign_response::Outcome::RejectedReason(r)),
            }))
        };
        // Nonces leave the map here whatever happens next: one Sign per Commit.
        let Some(pending) = self
            .pending
            .lock()
            .unwrap()
            .remove(&(fp, req.job_id.clone()))
        else {
            return reject("no commitment for this job".into());
        };
        let mut packages = Vec::with_capacity(req.signing_packages.len());
        for p in &req.signing_packages {
            match SigningPackage::deserialize(p) {
                Ok(p) => packages.push(p),
                Err(e) => return reject(format!("signing package: {e}")),
            }
        }
        let shares = match zd_pczt::frost::sign(pending.nonces, &packages, kp) {
            Ok(s) => s,
            Err(e) => return reject(e.to_string()),
        };
        Ok(Response::new(FrostSignResponse {
            job_id: req.job_id,
            outcome: Some(frost_sign_response::Outcome::Shares(FrostShares {
                per_spend: shares.iter().map(|s| s.serialize()).collect(),
            })),
        }))
    }
}

/// A FROST account as the coordinator sees it.
pub struct FrostAccount {
    /// Group key and verifying shares, from the ceremony.
    pub public_key_package: PublicKeyPackage,
    /// One client per member.
    pub members: Vec<FrostParticipantClient<Channel>>,
}

/// The `Signer` service of FROST accounts.
pub struct FrostCoordinatorService {
    accounts: HashMap<Vec<u8>, FrostAccount>,
}

impl FrostCoordinatorService {
    /// `accounts` is keyed by UFVK fingerprint.
    pub fn new(accounts: HashMap<Vec<u8>, FrostAccount>) -> Self {
        FrostCoordinatorService { accounts }
    }
}

/// Member index in `FrostAccount::members` -> (identifier, commitments).
type Committed = BTreeMap<Identifier, (usize, Vec<SigningCommitments>)>;

async fn collect_commitments(
    account: &FrostAccount,
    job: &SignJob,
    request: &SigningRequest,
) -> (Committed, Vec<String>) {
    let mut set = JoinSet::new();
    for (idx, client) in account.members.iter().enumerate() {
        let mut client = client.clone();
        let req = FrostCommitRequest {
            job_id: job.job_id.clone(),
            account: job.account.clone(),
            pczt: job.pczt.clone(),
            memo: job.memo.clone(),
        };
        set.spawn(async move { (idx, client.commit(req).await) });
    }
    let digest = sighash_digest(&request.sighash);
    let mut committed = BTreeMap::new();
    let mut problems = Vec::new();
    while let Some(r) = set.join_next().await {
        let (idx, resp) = match r {
            Ok((idx, Ok(resp))) => (idx, resp.into_inner()),
            Ok((idx, Err(status))) => {
                problems.push(format!("member #{idx} unreachable: {}", status.message()));
                continue;
            }
            Err(e) => {
                problems.push(format!("member task: {e}"));
                continue;
            }
        };
        let Ok(id) = Identifier::deserialize(&resp.identifier) else {
            problems.push(format!("member #{idx} sent a bad identifier"));
            continue;
        };
        match resp.outcome {
            Some(frost_commit_response::Outcome::Commitments(c)) => {
                if c.sighash_digest != digest || c.per_spend.len() != request.spends.len() {
                    problems.push(format!("member #{idx} sees a different transaction"));
                    continue;
                }
                let parsed: Result<Vec<_>, _> = c
                    .per_spend
                    .iter()
                    .map(|b| SigningCommitments::deserialize(b))
                    .collect();
                match parsed {
                    Ok(v) if !committed.contains_key(&id) => {
                        committed.insert(id, (idx, v));
                    }
                    Ok(_) => problems.push(format!("member #{idx} reused an identifier")),
                    Err(e) => problems.push(format!("member #{idx} commitments: {e}")),
                }
            }
            Some(frost_commit_response::Outcome::RejectedReason(r)) => {
                problems.push(format!("member #{idx} declined: {r}"))
            }
            None => problems.push(format!("member #{idx} sent no outcome")),
        }
    }
    (committed, problems)
}

#[tonic::async_trait]
impl Signer for FrostCoordinatorService {
    async fn sign(&self, request: Request<SignJob>) -> Result<Response<SignResult>, Status> {
        let job = request.into_inner();
        let fp = crate::fingerprint(&job.account)?;
        let account = self.accounts.get(&fp).ok_or_else(|| {
            Status::not_found(format!("unknown FROST account {}", crate::fp_hex(&fp)))
        })?;
        let reject = |r: String| {
            Ok(Response::new(SignResult {
                job_id: job.job_id.clone(),
                outcome: Some(sign_result::Outcome::RejectedReason(r)),
            }))
        };

        let pczt = match Pczt::parse(&job.pczt) {
            Ok(p) => p,
            Err(e) => return reject(format!("parse: {e:?}")),
        };
        let ak = ak_of(account.public_key_package.verifying_key())?;
        let signing = match zd_pczt::signing_request(&pczt, &ak) {
            Ok(r) => r,
            Err(e) => return reject(e.to_string()),
        };

        // Round 1: everyone; keep the first `threshold` by identifier.
        let threshold = usize::from(
            account
                .public_key_package
                .min_signers()
                .ok_or_else(|| Status::internal("public key package has no threshold"))?,
        );
        let (mut committed, problems) = collect_commitments(account, &job, &signing).await;
        if committed.len() < threshold {
            // Members that did commit still drop their nonces on a Sign
            // with no packages.
            release(account, &job, committed.values().map(|(i, _)| *i)).await;
            return reject(format!(
                "only {} of {threshold} required members committed: {}",
                committed.len(),
                problems.join("; ")
            ));
        }
        let mut extra = Vec::new();
        while committed.len() > threshold {
            let (_, (idx, _)) = committed.pop_last().expect("nonempty");
            extra.push(idx);
        }
        release(account, &job, extra).await;

        let commitments: BTreeMap<Identifier, Vec<SigningCommitments>> = committed
            .iter()
            .map(|(id, (_, c))| (*id, c.clone()))
            .collect();
        let packages = zd_pczt::frost::signing_packages(&signing, &commitments);
        let mut encoded = Vec::with_capacity(packages.len());
        for p in &packages {
            encoded.push(
                p.serialize()
                    .map_err(|e| Status::internal(format!("signing package: {e}")))?,
            );
        }

        // Round 2: exactly the chosen members.
        let mut set = JoinSet::new();
        for (id, (idx, _)) in &committed {
            let mut client = account.members[*idx].clone();
            let req = FrostSignRequest {
                job_id: job.job_id.clone(),
                account: job.account.clone(),
                signing_packages: encoded.clone(),
            };
            let id = *id;
            set.spawn(async move { (id, client.sign(req).await) });
        }
        let mut shares: BTreeMap<Identifier, Vec<SignatureShare>> = BTreeMap::new();
        let mut problems = Vec::new();
        while let Some(r) = set.join_next().await {
            let (id, resp) = match r {
                Ok(x) => x,
                Err(e) => {
                    problems.push(format!("member task: {e}"));
                    continue;
                }
            };
            match resp.map(|r| r.into_inner().outcome) {
                Ok(Some(frost_sign_response::Outcome::Shares(s))) => {
                    let parsed: Result<Vec<_>, _> = s
                        .per_spend
                        .iter()
                        .map(|b| SignatureShare::deserialize(b))
                        .collect();
                    match parsed {
                        Ok(v) if v.len() == signing.spends.len() => {
                            shares.insert(id, v);
                        }
                        _ => problems.push(format!("member {id:?}: malformed shares")),
                    }
                }
                Ok(Some(frost_sign_response::Outcome::RejectedReason(r))) => {
                    problems.push(format!("member {id:?} declined: {r}"))
                }
                Ok(None) => problems.push(format!("member {id:?}: no outcome")),
                Err(status) => problems.push(format!("member {id:?}: {}", status.message())),
            }
        }
        if shares.len() < threshold {
            return reject(format!("signing round failed: {}", problems.join("; ")));
        }

        let sigs = match zd_pczt::frost::aggregate(
            &signing,
            &packages,
            &shares,
            &account.public_key_package,
        ) {
            Ok(s) => s,
            Err(e) => {
                return reject(format!(
                    "aggregation failed (culprits {:?}): {e}",
                    e.culprits()
                ));
            }
        };
        match zd_pczt::apply_signatures(pczt, &sigs).and_then(|p| {
            p.serialize()
                .map_err(|e| zd_pczt::Error::Pczt(format!("{e:?}")))
        }) {
            Ok(bytes) => Ok(Response::new(SignResult {
                job_id: job.job_id,
                outcome: Some(sign_result::Outcome::SignedPczt(bytes)),
            })),
            Err(e) => reject(e.to_string()),
        }
    }
}

/// Tells members that committed but will not be asked to sign to drop their
/// nonces (a Sign with no packages consumes them and fails).
async fn release(account: &FrostAccount, job: &SignJob, members: impl IntoIterator<Item = usize>) {
    let mut set = JoinSet::new();
    for idx in members {
        let mut client = account.members[idx].clone();
        let req = FrostSignRequest {
            job_id: job.job_id.clone(),
            account: job.account.clone(),
            signing_packages: Vec::new(),
        };
        set.spawn(async move { client.sign(req).await });
    }
    while set.join_next().await.is_some() {}
}
