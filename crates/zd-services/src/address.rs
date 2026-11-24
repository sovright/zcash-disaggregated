//! The AddressService.

use std::collections::HashMap;
use std::sync::Mutex;

use orchard::keys::IncomingViewingKey;
use tonic::{Request, Response, Status};
use zcash_protocol::consensus::NetworkType;
use zd_address::AddressServer;
use zd_proto::v1::{AddressRequest, AddressResponse, address_service_server::AddressService};

/// Durable per-account counters. `store` must be durable before it returns,
/// or a restart could reissue an address.
pub trait CounterStore: Send + Sync + 'static {
    /// The number of addresses already issued for `account`.
    fn load(&self, account: &[u8]) -> u128;
    /// Records that `issued` addresses have now been issued.
    fn store(&self, account: &[u8], issued: u128) -> Result<(), String>;
}

/// In-memory counters. Loses state on restart; tests only.
#[derive(Default)]
pub struct MemoryCounters(Mutex<HashMap<Vec<u8>, u128>>);

impl CounterStore for MemoryCounters {
    fn load(&self, account: &[u8]) -> u128 {
        *self.0.lock().unwrap().get(account).unwrap_or(&0)
    }
    fn store(&self, account: &[u8], issued: u128) -> Result<(), String> {
        self.0.lock().unwrap().insert(account.to_vec(), issued);
        Ok(())
    }
}

/// Mints addresses for the accounts whose external IVKs it holds.
pub struct AddressServiceImpl<S> {
    server_id: u8,
    accounts: Mutex<HashMap<Vec<u8>, AddressServer>>,
    counters: S,
}

impl<S: CounterStore> AddressServiceImpl<S> {
    /// `accounts` maps UFVK fingerprint to (network, external IVK).
    pub fn new(
        server_id: u8,
        accounts: impl IntoIterator<Item = (Vec<u8>, NetworkType, IncomingViewingKey)>,
        counters: S,
    ) -> Self {
        let accounts = accounts
            .into_iter()
            .map(|(fp, net, ivk)| {
                let next = counters.load(&fp);
                (fp, AddressServer::new(ivk, net, server_id, next))
            })
            .collect();
        AddressServiceImpl {
            server_id,
            accounts: Mutex::new(accounts),
            counters,
        }
    }
}

#[tonic::async_trait]
impl<S: CounterStore> AddressService for AddressServiceImpl<S> {
    async fn new_address(
        &self,
        request: Request<AddressRequest>,
    ) -> Result<Response<AddressResponse>, Status> {
        let req = request.into_inner();
        let fp = crate::fingerprint(&req.account)?;
        let mut accounts = self.accounts.lock().unwrap();
        let server = accounts
            .get_mut(&fp)
            .ok_or_else(|| Status::not_found(format!("unknown account {}", crate::fp_hex(&fp))))?;
        let issued = server
            .next_address()
            .map_err(|e| Status::resource_exhausted(e.to_string()))?;
        // Persist before handing the address out.
        self.counters
            .store(&fp, server.issued())
            .map_err(|e| Status::unavailable(format!("counter store: {e}")))?;
        Ok(Response::new(AddressResponse {
            account: req.account,
            unified_address: issued.unified_address,
            diversifier_index: issued.diversifier_index.to_vec(),
            server_id: self.server_id.into(),
            label: req.label,
        }))
    }
}
