//! `zd`: every role of a disaggregated Orchard-protocol wallet as one binary.
//!
//! See `docs/deploy.md` for a walk-through. Each server subcommand serves one
//! role over gRPC; `--cert`, `--key` and `--ca` turn on TLS, and with `--ca`
//! a server also requires client certificates from that CA (mTLS).

mod files;
mod net;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use tonic::transport::{
    Certificate, Channel, ClientTlsConfig, Endpoint, Identity as TlsIdentity, Server,
    ServerTlsConfig,
};
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zd_proto::v1::{
    AddressRequest, BalanceRequest, SendRequest, address_service_client::AddressServiceClient,
    address_service_server::AddressServiceServer, frost_participant_client::FrostParticipantClient,
    frost_participant_server::FrostParticipantServer, key_ceremony_client::KeyCeremonyClient,
    key_ceremony_server::KeyCeremonyServer, prover_client::ProverClient,
    prover_server::ProverServer, signer_client::SignerClient, signer_server::SignerServer,
    wallet_client::WalletClient, wallet_ingest_client::WalletIngestClient,
    wallet_ingest_server::WalletIngestServer, wallet_server::WalletServer,
};
use zd_services::{
    address::{AddressServiceImpl, CounterStore},
    ceremony::{CeremonyRelay, Identity},
    frost::{FrostAccount, FrostCoordinatorService, FrostParticipantService},
    prover::{ProverService, ProvingKeys},
    signer::{AllowAll, SignerAccount, SingleSignerService},
};
use zd_wallet::{
    WalletDb,
    server::{FollowConfig, IngestService, WalletService, WalletState, follow_chain, fresh_trees},
};

use files::{
    AccountFile, IdentityFile, MemberFile, NetName, ParamsFile, ParticipantEntry, RecoveryFile,
    SECRET_HEADER, SignerKeyFile,
};

#[derive(Parser)]
#[command(name = "zd", version, about = "Disaggregated Zcash wallet roles")]
struct Cli {
    #[command(flatten)]
    tls: TlsOpts,
    #[command(subcommand)]
    cmd: Cmd,
}

/// TLS for every server and client this process runs.
#[derive(Args, Clone, Default)]
struct TlsOpts {
    /// PEM certificate chain this process presents (as server and as client).
    #[arg(long, global = true, env = "ZD_TLS_CERT")]
    cert: Option<PathBuf>,
    /// PEM private key for `--cert`.
    #[arg(long, global = true, env = "ZD_TLS_KEY")]
    key: Option<PathBuf>,
    /// PEM CA that peers' certificates must chain to. On servers this
    /// requires client certificates.
    #[arg(long, global = true, env = "ZD_TLS_CA")]
    ca: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Ceremony participant identities.
    #[command(subcommand)]
    Identity(IdentityCmd),
    /// Distributed key generation for a FROST account.
    #[command(subcommand)]
    Ceremony(CeremonyCmd),
    /// Prover role.
    Prover {
        #[arg(long, default_value = "0.0.0.0:7101")]
        listen: SocketAddr,
        /// Proofs to create at once.
        #[arg(long, default_value_t = 2)]
        concurrency: usize,
        /// Also load the pre-Ironwood Orchard proving key (Orchard-pool spends).
        #[arg(long)]
        orchard: bool,
    },
    /// 1/1 signer role, holding `ask` for each account.
    Signer {
        #[arg(long, default_value = "0.0.0.0:7102")]
        listen: SocketAddr,
        /// Account files, paired in order with `--signing-key`.
        #[arg(long = "account", required = true)]
        accounts: Vec<PathBuf>,
        #[arg(long = "signing-key", required = true)]
        keys: Vec<PathBuf>,
    },
    /// One member of a FROST signing quorum.
    FrostMember {
        #[arg(long, default_value = "0.0.0.0:7103")]
        listen: SocketAddr,
        /// Member key files (`frost-member.toml`), one per account.
        #[arg(long = "key-package", required = true)]
        key_packages: Vec<PathBuf>,
    },
    /// The `Signer` service of a FROST account: drives its members.
    FrostCoordinator {
        #[arg(long, default_value = "0.0.0.0:7102")]
        listen: SocketAddr,
        /// The account (must carry its public key package).
        #[arg(long)]
        account: PathBuf,
        /// Member endpoints, e.g. https://member-1:7103.
        #[arg(long = "member", required = true)]
        members: Vec<String>,
    },
    /// Address service.
    Address {
        #[arg(long, default_value = "0.0.0.0:7104")]
        listen: SocketAddr,
        /// This server's id: the top byte of every diversifier index it issues.
        #[arg(long)]
        server_id: u8,
        #[arg(long = "account", required = true)]
        accounts: Vec<PathBuf>,
        /// Directory for the durable address counters.
        #[arg(long)]
        counters: PathBuf,
    },
    /// Asks an address service for a new address.
    NewAddress {
        #[arg(long)]
        server: String,
        #[arg(long)]
        account: PathBuf,
        #[arg(long, default_value = "deposit")]
        purpose: String,
        #[arg(long, default_value = "")]
        label: String,
    },
    /// Detector role: scans compact blocks and reports to wallet state.
    Detector {
        #[arg(long, env = "ZD_LIGHTWALLETD")]
        lightwalletd: String,
        /// Wallet state's ingest endpoint.
        #[arg(long)]
        wallet: String,
        #[arg(long)]
        account: PathBuf,
        /// File holding the next height to scan.
        #[arg(long)]
        state: PathBuf,
        /// Height to start from if `--state` does not exist yet.
        #[arg(long)]
        from: Option<u64>,
        #[arg(long, default_value_t = 100)]
        batch: u64,
        #[arg(long, default_value_t = 15)]
        poll_secs: u64,
    },
    /// Wallet state role.
    #[command(subcommand)]
    Wallet(WalletCmd),
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// Generates an identity and prints its `[[participant]]` entry.
    Keygen {
        #[arg(long)]
        instance: String,
        /// FROST identifier to list in the entry.
        #[arg(long)]
        id: u32,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum CeremonyCmd {
    /// Writes `params.toml` from participant entries.
    Params {
        #[arg(long)]
        threshold: u32,
        #[arg(long, value_enum)]
        network: NetName,
        #[arg(long)]
        label: String,
        /// Files each holding one participant's `[[participant]]` entry.
        #[arg(long = "participant", required = true)]
        participants: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Relays one ceremony's messages. Holds no secrets.
    Relay {
        #[arg(long, default_value = "0.0.0.0:7105")]
        listen: SocketAddr,
        #[arg(long)]
        params: PathBuf,
    },
    /// Takes part in a ceremony and writes this participant's key files.
    Join {
        #[arg(long)]
        relay: String,
        #[arg(long)]
        params: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        me: u32,
        /// Directory for account.toml, frost-member.toml and recovery.toml.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum WalletCmd {
    /// Adds an account to the wallet database.
    AddAccount {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        account: PathBuf,
        /// First block that can hold the account's notes.
        #[arg(long)]
        birthday: u64,
    },
    /// Serves `WalletIngest` (for detectors) and `Wallet` (for operators).
    Serve {
        #[arg(long, default_value = "0.0.0.0:7100")]
        listen: SocketAddr,
        #[arg(long)]
        db: PathBuf,
        #[arg(long, value_enum)]
        network: NetName,
        /// Regtest only: height at which every upgrade activates.
        #[arg(long, default_value_t = 1)]
        regtest_activation: u32,
        #[arg(long, env = "ZD_LIGHTWALLETD")]
        lightwalletd: String,
        #[arg(long)]
        prover: String,
        #[arg(long)]
        signer: String,
        /// Blocks the commitment trees stay behind the tip.
        #[arg(long, default_value_t = 3)]
        confirmations: u32,
    },
    /// Shows an account's spendable balance.
    Balance {
        #[arg(long)]
        wallet: String,
        #[arg(long)]
        account: PathBuf,
    },
    /// Sends from an account.
    Send {
        #[arg(long)]
        wallet: String,
        #[arg(long)]
        account: PathBuf,
        /// Unified address (or raw Orchard address hex).
        #[arg(long)]
        to: String,
        /// Zatoshis.
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value = "")]
        memo: String,
        /// Reason shown to signer approvers.
        #[arg(long, default_value = "")]
        reason: String,
        #[arg(long)]
        broadcast: bool,
    },
}

fn read_pem(p: &Path) -> Result<Vec<u8>> {
    std::fs::read(p).with_context(|| format!("reading {}", p.display()))
}

impl TlsOpts {
    fn server(&self) -> Result<Server> {
        let mut s = Server::builder();
        match (&self.cert, &self.key) {
            (Some(c), Some(k)) => {
                let mut cfg = ServerTlsConfig::new()
                    .identity(TlsIdentity::from_pem(read_pem(c)?, read_pem(k)?));
                if let Some(ca) = &self.ca {
                    cfg = cfg.client_ca_root(Certificate::from_pem(read_pem(ca)?));
                }
                s = s.tls_config(cfg)?;
            }
            (None, None) => {
                if self.ca.is_some() {
                    bail!("--ca on a server needs --cert and --key");
                }
                tracing::warn!("serving without TLS; use only on a trusted network");
            }
            _ => bail!("--cert and --key go together"),
        }
        Ok(s)
    }

    fn endpoint(&self, url: &str) -> Result<Endpoint> {
        let mut e = Endpoint::from_shared(url.to_string())?;
        if url.starts_with("https://") {
            let mut cfg = ClientTlsConfig::new().with_webpki_roots();
            if let Some(ca) = &self.ca {
                cfg = cfg.ca_certificate(Certificate::from_pem(read_pem(ca)?));
            }
            if let (Some(c), Some(k)) = (&self.cert, &self.key) {
                cfg = cfg.identity(TlsIdentity::from_pem(read_pem(c)?, read_pem(k)?));
            }
            e = e.tls_config(cfg)?;
        }
        Ok(e)
    }

    /// Connects when first used, so roles can start in any order.
    fn lazy(&self, url: &str) -> Result<Channel> {
        Ok(self.endpoint(url)?.connect_lazy())
    }

    async fn connect(&self, url: &str) -> Result<Channel> {
        self.endpoint(url)?
            .connect()
            .await
            .with_context(|| format!("connecting to {url}"))
    }
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}

/// Counters in a directory, one file per account, written atomically.
struct FileCounters(PathBuf);

impl CounterStore for FileCounters {
    fn load(&self, account: &[u8]) -> u128 {
        std::fs::read_to_string(self.0.join(hex::encode(account)))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }
    fn store(&self, account: &[u8], issued: u128) -> Result<(), String> {
        files::write_atomic(
            &self.0.join(hex::encode(account)),
            issued.to_string().as_bytes(),
            false,
        )
        .map_err(|e| e.to_string())
    }
}

fn load_accounts(paths: &[PathBuf]) -> Result<Vec<AccountFile>> {
    paths.iter().map(|p| files::read(p)).collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let tls = cli.tls;
    match cli.cmd {
        Cmd::Identity(IdentityCmd::Keygen { instance, id, out }) => {
            let identity = Identity::generate(instance);
            files::write(
                &out,
                SECRET_HEADER,
                &IdentityFile::from_identity(&identity),
                true,
            )?;
            #[derive(serde::Serialize)]
            struct One {
                participant: Vec<ParticipantEntry>,
            }
            print!(
                "{}",
                toml::to_string_pretty(&One {
                    participant: vec![ParticipantEntry::from_identity(id, &identity)],
                })?
            );
        }

        Cmd::Ceremony(CeremonyCmd::Params {
            threshold,
            network,
            label,
            participants,
            out,
        }) => {
            #[derive(serde::Deserialize)]
            struct One {
                participant: Vec<ParticipantEntry>,
            }
            let mut entries = Vec::new();
            for p in &participants {
                entries.extend(files::read::<One>(p)?.participant);
            }
            let mut nonce = [0u8; 32];
            rand::fill(&mut nonce);
            let params = ParamsFile {
                threshold,
                network,
                label,
                nonce: hex::encode(nonce),
                participants: entries,
            };
            params.proto()?;
            files::write(
                &out,
                "# Ceremony parameters. Every participant must use this exact file.",
                &params,
                false,
            )?;
            println!(
                "transcript id {}",
                hex::encode(zd_services::ceremony::transcript_id(&params.proto()?))
            );
        }

        Cmd::Ceremony(CeremonyCmd::Relay { listen, params }) => {
            let params = files::read::<ParamsFile>(&params)?.proto()?;
            let relay = CeremonyRelay::new(params).map_err(|e| anyhow!("{e}"))?;
            tracing::info!(%listen, "ceremony relay");
            tls.server()?
                .add_service(KeyCeremonyServer::new(relay))
                .serve_with_shutdown(listen, shutdown())
                .await?;
        }

        Cmd::Ceremony(CeremonyCmd::Join {
            relay,
            params,
            identity,
            me,
            out,
        }) => {
            let pf: ParamsFile = files::read(&params)?;
            let identity = files::read::<IdentityFile>(&identity)?.identity()?;
            let client = KeyCeremonyClient::new(tls.connect(&relay).await?);
            tracing::info!(
                transcript = hex::encode(zd_services::ceremony::transcript_id(&pf.proto()?)),
                "joining ceremony"
            );
            let keys = zd_services::ceremony::run_participant(client, pf.proto()?, me, &identity)
                .await
                .map_err(|e| anyhow!("ceremony: {e}"))?;
            std::fs::create_dir_all(&out)?;
            let pkp = keys
                .public_key_package()
                .serialize()
                .map_err(|e| anyhow!("{e}"))?;
            let account = AccountFile::new(
                pf.network,
                &pf.label,
                keys.account().fvk(),
                Some(*keys.account().qk().as_bytes()),
                Some(pkp),
            );
            let fp = account.fingerprint.clone();
            files::write(
                &out.join("account.toml"),
                "# Account viewing material. The UFVK reveals all of the account's transactions.",
                &account,
                false,
            )?;
            files::write(
                &out.join("frost-member.toml"),
                SECRET_HEADER,
                &MemberFile {
                    fingerprint: fp.clone(),
                    key_package: hex::encode(
                        keys.key_package().serialize().map_err(|e| anyhow!("{e}"))?,
                    ),
                },
                true,
            )?;
            files::write(
                &out.join("recovery.toml"),
                &format!(
                    "{SECRET_HEADER}\n# Every participant holds the same sk and qsk. Store offline."
                ),
                &RecoveryFile {
                    fingerprint: fp.clone(),
                    sk: hex::encode(keys.sk().as_bytes()),
                    qsk: hex::encode(keys.qsk().as_bytes()),
                },
                true,
            )?;
            println!("account {fp}\n{}", account.ufvk);
        }

        Cmd::Prover {
            listen,
            concurrency,
            orchard,
        } => {
            tracing::info!("building proving keys");
            let mut keys = ProvingKeys::ironwood();
            if orchard {
                keys.orchard = Some(orchard::circuit::ProvingKey::build(
                    orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2,
                ));
            }
            tracing::info!(%listen, "prover");
            tls.server()?
                .add_service(ProverServer::new(ProverService::new(keys, concurrency)))
                .serve_with_shutdown(listen, shutdown())
                .await?;
        }

        Cmd::Signer {
            listen,
            accounts,
            keys,
        } => {
            if accounts.len() != keys.len() {
                bail!("give one --signing-key per --account");
            }
            let mut map = HashMap::new();
            for (a, k) in accounts.iter().zip(&keys) {
                let a: AccountFile = files::read(a)?;
                let k: SignerKeyFile = files::read(k)?;
                if k.fingerprint != a.fingerprint {
                    bail!("signing key {} is for another account", k.fingerprint);
                }
                let ask = orchard::primitives::redpallas::SigningKey::try_from(files::unhex::<32>(
                    "ask", &k.ask,
                )?)
                .map_err(|_| anyhow!("ask is not a valid scalar"))?;
                let ak: [u8; 32] =
                    (&orchard::primitives::redpallas::VerificationKey::from(&ask)).into();
                let (_, fvk) =
                    zd_address::keys::parse_ufvk(&a.ufvk).ok_or_else(|| anyhow!("bad ufvk"))?;
                if fvk.to_bytes()[..32] != ak {
                    bail!("ask does not match the account's ak");
                }
                map.insert(a.fingerprint()?.to_vec(), SignerAccount { ak, ask });
            }
            tracing::info!(%listen, accounts = map.len(), "1/1 signer");
            tls.server()?
                .add_service(SignerServer::new(SingleSignerService::new(map, AllowAll)))
                .serve_with_shutdown(listen, shutdown())
                .await?;
        }

        Cmd::FrostMember {
            listen,
            key_packages,
        } => {
            let mut map = HashMap::new();
            for p in &key_packages {
                let m: MemberFile = files::read(p)?;
                let kp = zd_frost::keys::KeyPackage::deserialize(
                    &hex::decode(&m.key_package).context("key_package hex")?,
                )
                .map_err(|e| anyhow!("key package: {e}"))?;
                map.insert(
                    files::unhex::<32>("fingerprint", &m.fingerprint)?.to_vec(),
                    kp,
                );
            }
            tracing::info!(%listen, accounts = map.len(), "FROST member");
            tls.server()?
                .add_service(FrostParticipantServer::new(FrostParticipantService::new(
                    map, AllowAll,
                )))
                .serve_with_shutdown(listen, shutdown())
                .await?;
        }

        Cmd::FrostCoordinator {
            listen,
            account,
            members,
        } => {
            let a: AccountFile = files::read(&account)?;
            if a.public_key_package.is_empty() {
                bail!("account file has no public_key_package");
            }
            let pkp = zd_frost::keys::PublicKeyPackage::deserialize(
                &hex::decode(&a.public_key_package).context("public_key_package hex")?,
            )
            .map_err(|e| anyhow!("public key package: {e}"))?;
            let members = members
                .iter()
                .map(|m| Ok(FrostParticipantClient::new(tls.lazy(m)?)))
                .collect::<Result<Vec<_>>>()?;
            let mut map = HashMap::new();
            map.insert(
                a.fingerprint()?.to_vec(),
                FrostAccount {
                    public_key_package: pkp,
                    members,
                },
            );
            tracing::info!(%listen, "FROST coordinator");
            tls.server()?
                .add_service(SignerServer::new(FrostCoordinatorService::new(map)))
                .serve_with_shutdown(listen, shutdown())
                .await?;
        }

        Cmd::Address {
            listen,
            server_id,
            accounts,
            counters,
        } => {
            std::fs::create_dir_all(&counters)?;
            let accts = load_accounts(&accounts)?
                .into_iter()
                .map(|a| {
                    Ok((
                        a.fingerprint()?.to_vec(),
                        a.network.network_type(),
                        a.external_ivk()?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            tracing::info!(%listen, server_id, "address service");
            tls.server()?
                .add_service(AddressServiceServer::new(AddressServiceImpl::new(
                    server_id,
                    accts,
                    FileCounters(counters),
                )))
                .serve_with_shutdown(listen, shutdown())
                .await?;
        }

        Cmd::NewAddress {
            server,
            account,
            purpose,
            label,
        } => {
            let a: AccountFile = files::read(&account)?;
            let r = AddressServiceClient::new(tls.connect(&server).await?)
                .new_address(AddressRequest {
                    account: Some(a.account_ref()?),
                    purpose,
                    label,
                })
                .await?
                .into_inner();
            println!("{}", r.unified_address);
        }

        Cmd::Detector {
            lightwalletd,
            wallet,
            account,
            state,
            from,
            batch,
            poll_secs,
        } => {
            let a: AccountFile = files::read(&account)?;
            let detector =
                zd_detect::Detector::new(a.account_ref()?, &a.external_ivk()?, &a.internal_ivk()?);
            let next = match files::read_height(&state)? {
                Some(h) => h,
                None => from.ok_or_else(|| anyhow!("no --state yet; give --from"))?,
            };
            let mut source = CompactTxStreamerClient::new(tls.connect(&lightwalletd).await?);
            let mut ingest = WalletIngestClient::new(tls.lazy(&wallet)?);
            tracing::info!(next, "detector");
            let state_path = state.clone();
            zd_services::detector::follow(
                &mut source,
                &detector,
                &mut ingest,
                next,
                batch,
                Duration::from_secs(poll_secs),
                move |h| {
                    if let Err(e) =
                        files::write_atomic(&state_path, h.to_string().as_bytes(), false)
                    {
                        tracing::error!(error = %e, "could not save detector state");
                    }
                },
            )
            .await
            .map_err(|e| anyhow!("detector: {e}"))?;
        }

        Cmd::Wallet(WalletCmd::AddAccount {
            db,
            account,
            birthday,
        }) => {
            let a: AccountFile = files::read(&account)?;
            let db = WalletDb::open(&db)?;
            let fp = db.add_account(&a.ufvk, a.qk()?, &a.label, birthday)?;
            println!("added {}", hex::encode(fp));
        }

        Cmd::Wallet(WalletCmd::Serve {
            listen,
            db,
            network,
            regtest_activation,
            lightwalletd,
            prover,
            signer,
            confirmations,
        }) => {
            let db = WalletDb::open(&db)?;
            let mut lwd = CompactTxStreamerClient::new(tls.connect(&lightwalletd).await?);
            let birthday = db.earliest_birthday().context("add an account first")?;
            let trees = fresh_trees(birthday, &mut lwd).await?;
            db.mark_all_unconfirmed()?;
            let state = WalletState::new(db, trees, net::Net::new(network, regtest_activation));

            let cfg = FollowConfig {
                confirmations,
                ..Default::default()
            };
            let (st, mut src) = (state.clone(), lwd.clone());
            tokio::spawn(async move { follow_forever(st, &mut src, cfg).await });

            let svc = WalletService::new(
                state.clone(),
                ProverClient::new(tls.lazy(&prover)?),
                SignerClient::new(tls.lazy(&signer)?),
                Some(lwd),
            );
            tracing::info!(%listen, "wallet state");
            tls.server()?
                .add_service(WalletIngestServer::new(IngestService(state)))
                .add_service(WalletServer::new(svc))
                .serve_with_shutdown(listen, shutdown())
                .await?;
        }

        Cmd::Wallet(WalletCmd::Balance { wallet, account }) => {
            let a: AccountFile = files::read(&account)?;
            let b = WalletClient::new(tls.connect(&wallet).await?)
                .get_balance(BalanceRequest {
                    account: Some(a.account_ref()?),
                })
                .await?
                .into_inner();
            println!(
                "ironwood {} zat\norchard  {} zat\nas of block {}",
                b.ironwood_zat, b.orchard_zat, b.tree_height
            );
        }

        Cmd::Wallet(WalletCmd::Send {
            wallet,
            account,
            to,
            amount,
            memo,
            reason,
            broadcast,
        }) => {
            let a: AccountFile = files::read(&account)?;
            let r = WalletClient::new(tls.connect(&wallet).await?)
                .send(SendRequest {
                    account: Some(a.account_ref()?),
                    recipient: to,
                    amount_zat: amount,
                    memo: memo.into_bytes(),
                    broadcast,
                    reason,
                })
                .await?
                .into_inner();
            let mut txid = r.txid.clone();
            txid.reverse();
            println!(
                "txid {}\nfee {} zat\n{}",
                hex::encode(txid),
                r.fee_zat,
                if r.broadcast {
                    "broadcast".to_string()
                } else {
                    format!("raw {}", hex::encode(r.raw_tx))
                }
            );
        }
    }
    Ok(())
}

/// Keeps the trees following the chain; rebuilds them from the birthday
/// when a reorg is deeper than the kept checkpoints.
async fn follow_forever(
    state: Arc<WalletState<net::Net>>,
    lwd: &mut CompactTxStreamerClient<Channel>,
    cfg: FollowConfig,
) {
    loop {
        let err = match follow_chain(&state, lwd, cfg, None).await {
            Ok(()) => return,
            Err(e) => e,
        };
        tracing::warn!(error = %err, "chain follower stopped; retrying");
        tokio::time::sleep(Duration::from_secs(10)).await;
        if let zd_wallet::Error::Tree(msg) = &err
            && msg.contains("rebuild")
        {
            let birthday = state.db.lock().expect("db lock").earliest_birthday();
            let rebuilt = match birthday {
                Ok(b) => fresh_trees(b, lwd).await,
                Err(e) => Err(e),
            };
            match rebuilt.and_then(|t| state.reset_trees(t)) {
                Ok(()) => tracing::info!("rebuilt commitment trees"),
                Err(e) => tracing::error!(error = %e, "tree rebuild failed"),
            }
        }
    }
}
