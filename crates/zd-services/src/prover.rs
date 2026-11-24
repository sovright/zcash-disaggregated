//! The Prover service.

use std::sync::Arc;
use std::time::Instant;

use pczt::Pczt;
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use tokio::sync::Semaphore;
use tonic::{Request, Response, Status};
use zd_proto::v1::{ProveJob, ProveResult, prove_result::Outcome, prover_server::Prover};

/// Proving keys, built once at startup (building one takes seconds).
pub struct ProvingKeys {
    /// Circuit for Orchard-pool bundles, if this prover serves them.
    pub orchard: Option<orchard::circuit::ProvingKey>,
    /// Circuit for Ironwood-pool bundles.
    pub ironwood: Option<orchard::circuit::ProvingKey>,
}

impl ProvingKeys {
    /// Ironwood only (`OrchardCircuitVersion::PostNu6_3`).
    pub fn ironwood() -> Self {
        ProvingKeys {
            orchard: None,
            ironwood: Some(orchard::circuit::ProvingKey::build(
                orchard::circuit::OrchardCircuitVersion::PostNu6_3,
            )),
        }
    }
}

/// Proves PCZTs. Holds no keys beyond the circuit parameters; it learns each
/// spend's FVK from the PCZT, so it must run inside the trust boundary.
pub struct ProverService {
    keys: Arc<ProvingKeys>,
    slots: Arc<Semaphore>,
}

impl ProverService {
    /// `concurrency` proofs at a time (each uses several cores).
    pub fn new(keys: ProvingKeys, concurrency: usize) -> Self {
        ProverService {
            keys: Arc::new(keys),
            slots: Arc::new(Semaphore::new(concurrency.max(1))),
        }
    }
}

#[tonic::async_trait]
impl Prover for ProverService {
    async fn prove(&self, request: Request<ProveJob>) -> Result<Response<ProveResult>, Status> {
        let job = request.into_inner();
        let _permit = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Status::unavailable("prover shutting down"))?;
        let keys = self.keys.clone();
        let started = Instant::now();
        let outcome = tokio::task::spawn_blocking(move || {
            let pczt = Pczt::parse(&job.pczt).map_err(|e| format!("parse: {e:?}"))?;
            let proved = zd_pczt::prove(
                pczt,
                keys.orchard.as_ref(),
                keys.ironwood.as_ref(),
                &mut UnwrapErr(SysRng),
            )
            .map_err(|e| e.to_string())?;
            proved.serialize().map_err(|e| format!("serialize: {e:?}"))
        })
        .await
        .map_err(|e| Status::internal(format!("prover task: {e}")))?;

        Ok(Response::new(ProveResult {
            job_id: job.job_id,
            outcome: Some(match outcome {
                Ok(bytes) => Outcome::ProvedPczt(bytes),
                Err(e) => Outcome::Error(e),
            }),
            prove_time_ms: started.elapsed().as_millis() as u64,
        }))
    }
}
