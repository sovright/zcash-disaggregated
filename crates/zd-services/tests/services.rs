//! The three services over real gRPC: an address server mints an address,
//! wallet state builds a PCZT spending a note to that account, the prover
//! service proves it, the 1/1 signer service signs it, and the transaction
//! extracts.

use std::collections::HashMap;

use orchard::tree::MerkleHashOrchard;
use pczt::Pczt;
use pczt::roles::{
    creator::Creator, io_finalizer::IoFinalizer, tx_extractor::TransactionExtractor,
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use rand_core_06::OsRng;
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};
use zcash_note_encryption::try_note_decryption;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding, PcztResult},
    fees::zip317,
};
use zcash_protocol::{
    consensus::{BlockHeight, NetworkType},
    memo::{Memo, MemoBytes},
    value::Zatoshis,
};
use zd_proto::v1::{
    AccountRef, AddressRequest, ProveJob, SignJob, address_service_client::AddressServiceClient,
    address_service_server::AddressServiceServer, prove_result, prover_client::ProverClient,
    prover_server::ProverServer, sign_result, signer_client::SignerClient,
    signer_server::SignerServer,
};
use zd_services::{
    address::{AddressServiceImpl, MemoryCounters},
    prover::{ProverService, ProvingKeys},
    signer::{AllowAll, Policy, SignerAccount, SingleSignerService},
};

fn network() -> zcash_protocol::local_consensus::LocalNetwork {
    let h = |n| Some(BlockHeight::from_u32(n));
    zcash_protocol::local_consensus::LocalNetwork {
        overwinter: h(1),
        sapling: h(2),
        blossom: h(3),
        heartwood: h(4),
        canopy: h(5),
        nu5: h(6),
        nu6: h(7),
        nu6_1: h(8),
        nu6_2: h(9),
        nu6_3: h(10),
        nu7: None,
    }
}

/// Wallet state's job: a PCZT spending one Ironwood note of the account.
fn build_pczt(fvk: &orchard::keys::FullViewingKey) -> Pczt {
    let mut rng = UnwrapErr(SysRng);
    let ivk = fvk.to_ivk(orchard::keys::Scope::External);
    let recipient = fvk.address_at(0u32, orchard::keys::Scope::External);

    // Receive an Ironwood (v3, quantum-recoverable) note; the detector's view.
    let note = {
        let v = orchard::bundle::BundleVersion::ironwood_v3();
        let mut b = orchard::builder::Builder::new(
            orchard::builder::BundleType::DEFAULT,
            v,
            v.default_flags(),
            orchard::Anchor::empty_tree(),
        )
        .unwrap();
        b.add_output(
            None,
            recipient,
            orchard::value::NoteValue::from_raw(1_000_000),
            Memo::Empty.encode().into_bytes(),
        )
        .unwrap();
        let (bundle, meta) = b.build::<i64>(&mut rng).unwrap().unwrap();
        let action = &bundle.actions()[meta.output_action_index(0).unwrap()];
        let domain = orchard::note_encryption::IronwoodDomain::for_action(action);
        let (note, _, _) = try_note_decryption(&domain, &ivk.prepare(), action)
            .expect("account IVK decrypts its Ironwood note");
        assert_eq!(note.version(), orchard::note::NoteVersion::V3);
        note
    };

    let (anchor, merkle_path): (orchard::Anchor, orchard::tree::MerklePath) = {
        let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        let mut tree =
            ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
        tree.append(leaf, incrementalmerkletree::Retention::Marked)
            .unwrap();
        tree.checkpoint(9_999_999).unwrap();
        let path = tree
            .witness_at_checkpoint_depth(0.into(), 0)
            .unwrap()
            .unwrap();
        let anchor = path.root(leaf);
        (anchor.into(), path.into())
    };

    let mut builder = Builder::new(
        network(),
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_ironwood_spend::<zip317::FeeRule>(fvk.clone(), note, merkle_path)
        .unwrap();
    builder
        .add_ironwood_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(orchard::keys::Scope::External)),
            fvk.address_at(7u32, orchard::keys::Scope::External),
            Zatoshis::const_from_u64(990_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult { pczt_parts, .. } = builder
        .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
        .unwrap();
    let unfinalized = Creator::build_from_parts(pczt_parts).unwrap();

    IoFinalizer::new(unfinalized)
        .finalize_io(UnwrapErr(SysRng))
        .unwrap()
}

struct Account {
    fp: Vec<u8>,
    ak: [u8; 32],
    ask: orchard::primitives::redpallas::SigningKey<orchard::primitives::redpallas::SpendAuth>,
    keys: zd_keys::AccountKeys,
}

fn hsm_account() -> Account {
    use ff::PrimeField;
    use zd_frost::Field;
    let s = zd_frost::PallasScalarField::random(&mut OsRng);
    let (s, ak) = zd_keys::zip2005::normalize_ask(s).unwrap();
    let ask = orchard::primitives::redpallas::SigningKey::try_from(s.to_repr()).unwrap();
    let (keys, _qsk) = zd_keys::AccountKeys::derive(&[3u8; 32], ak).unwrap();
    Account {
        fp: keys.fvk_hash().to_vec(),
        ak,
        ask,
        keys,
    }
}

async fn serve<S>(svc: S) -> Channel
where
    S: tower_service_bound::Svc,
{
    svc.serve().await
}

mod tower_service_bound {
    use super::*;
    pub trait Svc {
        fn serve(self) -> impl std::future::Future<Output = Channel>;
    }
    macro_rules! svc {
        ($t:ty) => {
            impl Svc for $t {
                async fn serve(self) -> Channel {
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let addr = listener.local_addr().unwrap();
                    tokio::spawn(
                        Server::builder()
                            .add_service(self)
                            .serve_with_incoming(TcpListenerStream::new(listener)),
                    );
                    Channel::from_shared(format!("http://{addr}"))
                        .unwrap()
                        .connect()
                        .await
                        .unwrap()
                }
            }
        };
    }
    svc!(AddressServerT);
    svc!(ProverServerT);
    svc!(SignerServerT);
    svc!(SignerServerRejectT);
    pub type AddressServerT = AddressServiceServer<AddressServiceImpl<MemoryCounters>>;
    pub type ProverServerT = ProverServer<ProverService>;
    pub type SignerServerT = SignerServer<SingleSignerService<AllowAll>>;
    pub type SignerServerRejectT = SignerServer<SingleSignerService<RejectAll>>;
}

pub struct RejectAll;
impl Policy for RejectAll {
    fn check(&self, _: &SignJob, _: &Pczt, _: &zd_pczt::SigningRequest) -> Result<(), String> {
        Err("no".into())
    }
}

fn account_ref(fp: &[u8]) -> Option<AccountRef> {
    Some(AccountRef {
        ufvk_fingerprint: fp.to_vec(),
        network: 0,
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn address_server_mints_distinct_addresses() {
    let acct = hsm_account();
    let ivk = acct.keys.fvk().to_ivk(orchard::keys::Scope::External);
    let ch = serve(AddressServiceServer::new(AddressServiceImpl::new(
        4,
        [(acct.fp.clone(), NetworkType::Main, ivk)],
        MemoryCounters::default(),
    )))
    .await;
    let mut client = AddressServiceClient::new(ch);
    let mut seen = std::collections::HashSet::new();
    for i in 0..3u8 {
        let r = client
            .new_address(AddressRequest {
                account: account_ref(&acct.fp),
                purpose: "deposit".into(),
                label: format!("quote-{i}"),
            })
            .await
            .unwrap()
            .into_inner();
        assert!(r.unified_address.starts_with("u1"));
        assert_eq!(r.server_id, 4);
        assert_eq!(r.diversifier_index[0], i);
        assert_eq!(r.diversifier_index[10], 4);
        assert_eq!(r.label, format!("quote-{i}"));
        assert!(seen.insert(r.unified_address));
    }
    let err = client
        .new_address(AddressRequest {
            account: account_ref(&[0; 32]),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test(flavor = "multi_thread")]
async fn prove_and_sign_over_grpc() {
    let acct = hsm_account();
    let pczt = build_pczt(acct.keys.fvk());
    let bytes = pczt.serialize().unwrap();

    let prover = ProverClient::new(
        serve(ProverServer::new(ProverService::new(
            ProvingKeys::ironwood(),
            1,
        )))
        .await,
    );
    let mut accounts = HashMap::new();
    accounts.insert(
        acct.fp.clone(),
        SignerAccount {
            ak: acct.ak,
            ask: acct.ask,
        },
    );
    let signer = SignerClient::new(
        serve(SignerServer::new(SingleSignerService::new(
            accounts, AllowAll,
        )))
        .await,
    );

    // Prove and sign in parallel, as wallet state would.
    let (mut p, mut sg) = (prover.clone(), signer.clone());
    let (proved, signed) = tokio::join!(
        p.prove(ProveJob {
            job_id: b"job-1".to_vec(),
            account: account_ref(&acct.fp),
            pczt: bytes.clone(),
            deadline_unix_ms: 0,
        }),
        sg.sign(SignJob {
            job_id: b"job-1".to_vec(),
            account: account_ref(&acct.fp),
            pczt: bytes.clone(),
            memo: String::new(),
        })
    );
    let proved = match proved.unwrap().into_inner().outcome.unwrap() {
        prove_result::Outcome::ProvedPczt(b) => Pczt::parse(&b).unwrap(),
        prove_result::Outcome::Error(e) => panic!("prover: {e}"),
    };
    let signed = match signed.unwrap().into_inner().outcome.unwrap() {
        sign_result::Outcome::SignedPczt(b) => Pczt::parse(&b).unwrap(),
        sign_result::Outcome::RejectedReason(r) => panic!("signer: {r}"),
    };

    // Wallet state combines the two and extracts.
    let combined = pczt::roles::combiner::Combiner::new(vec![proved, signed])
        .combine()
        .unwrap();
    TransactionExtractor::new(combined)
        .extract(UnwrapErr(SysRng))
        .expect("valid transaction");

    // Unknown account and garbage PCZT.
    let mut s = signer.clone();
    let err = s
        .sign(SignJob {
            account: account_ref(&[1; 32]),
            pczt: bytes.clone(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
    let r = s
        .sign(SignJob {
            account: account_ref(&acct.fp),
            pczt: vec![1, 2, 3],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(matches!(
        r.outcome,
        Some(sign_result::Outcome::RejectedReason(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_rejection_is_returned() {
    let acct = hsm_account();
    let pczt = build_pczt(acct.keys.fvk());
    let mut accounts = HashMap::new();
    accounts.insert(
        acct.fp.clone(),
        SignerAccount {
            ak: acct.ak,
            ask: acct.ask,
        },
    );
    let mut signer = SignerClient::new(
        serve(SignerServer::new(SingleSignerService::new(
            accounts, RejectAll,
        )))
        .await,
    );
    let r = signer
        .sign(SignJob {
            account: account_ref(&acct.fp),
            pczt: pczt.serialize().unwrap(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        r.outcome,
        Some(sign_result::Outcome::RejectedReason("policy: no".into()))
    );
}
